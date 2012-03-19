#!/usr/bin/perl -w

# This file contains tests of the external behavior of Ncat.

require HTTP::Response;
require HTTP::Request;

use MIME::Base64;
use File::Temp qw/ tempfile /;
use URI::Escape;
use Data::Dumper;
use Socket;

use IPC::Open3;
use strict;

my $NCAT = "../ncat";
my $HOST = "localhost";
my $IPV6_ADDR = "::1";
my $PORT = 40000;
my $PROXY_PORT = 40001;

my $BUFSIZ = 1024;

my $num_tests = 0;
my $num_failures = 0;
my $num_expected_failures = 0;
my $num_unexpected_passes = 0;

# If true during a test, failure is expected (XFAIL).
our $xfail = 0;

# Run $NCAT with the given arguments.
sub ncat {
	my $pid;
	local *IN;
	local *OUT;
	local *ERR;
	# print join(" ", ($NCAT, @_)) . "\n";
	$pid = open3(*IN, *OUT, *ERR, $NCAT, @_);
	if (!defined $pid) {
		die "open2 failed";
	}
	return ($pid, *OUT, *IN, *ERR);
}

sub ncat_server {
	return ncat($HOST, $PORT, "-l", @_);
}

sub ncat_client {
	my @ret = ncat($HOST, $PORT, @_);
	# Give it a moment to connect.
	select(undef, undef, undef, 0.1);
	return @ret;
}

# Kill all child processes.
sub kill_children {
	local $SIG{TERM} = "IGNORE";
	kill "TERM", -$$;
	while (waitpid(-1, 0) > 0) {
	}
}

# Read until a timeout occurs. Return undef on EOF or "" on timeout.
sub timeout_read {
	my $fh = shift;
	my $timeout = 0.50;
	if (scalar(@_) > 0) {
		$timeout = shift;
	}
	my $result = "";
	my $rd = "";
	my $frag;
	vec($rd, fileno($fh), 1) = 1;
	# Here we rely on $timeout being decremented after select returns,
	# which may not be supported on all systems.
	while (select($rd, undef, undef, $timeout) != 0) {
		return ($result or undef) if sysread($fh, $frag, $BUFSIZ) == 0;
		$result .= $frag;
	}
	return $result;
}

$Data::Dumper::Terse = 1;
$Data::Dumper::Useqq = 1;
$Data::Dumper::Indent = 0;
sub d {
	return Dumper(@_);
}

# Run the code reference received as an argument. Count it as a pass if the
# evaluation is successful, a failure otherwise.
sub test {
	my $desc = shift;
	my $code = shift;
	$num_tests++;
	if (eval { &$code() }) {
		if ($xfail) {
			print "UNEXPECTED PASS $desc\n";
			$num_unexpected_passes++;
		} else {
			print "PASS $desc\n";
		}
	} else {
		if ($xfail) {
			$num_expected_failures++;
			print "XFAIL $desc\n";
		} else {
			$num_failures++;
			print "FAIL $desc\n";
			print "     $@";
		}
	}
}

my ($s_pid, $s_out, $s_in, $c_pid, $c_out, $c_in, $p_pid, $p_out, $p_in);

# Handle a common test situation. Start up a server and client with the given
# arguments and call test on a code block. Within the code block the server's
# PID, output filehandle, and input filehandle are accessible through
#   $s_pid, $s_out, and $s_in
# and likewise for the client:
#   $c_pid, $c_out, and $c_in.
sub server_client_test {
	my $desc = shift;
	my $server_args = shift;
	my $client_args = shift;
	my $code = shift;
	($s_pid, $s_out, $s_in) = ncat_server(@$server_args);
	($c_pid, $c_out, $c_in) = ncat_client(@$client_args);
	test($desc, $code);
	kill_children;
}

sub server_client_test_multi {
	my $specs = shift;
	my $desc = shift;
	my $server_args_ref = shift;
	my $client_args_ref = shift;
	my $code = shift;
	my $outer_xfail = $xfail;
	local $xfail;

	for my $spec (@$specs) {
		my @server_args = @$server_args_ref;
		my @client_args = @$client_args_ref;

		$xfail = $outer_xfail;
		for my $proto (split(/ /, $spec)) {
			if ($proto eq "tcp") {
				# Nothing needed.
			} elsif ($proto eq "udp") {
				push @server_args, ("--udp");
				push @client_args, ("--udp");
			} elsif ($proto eq "sctp") {
				push @server_args, ("--sctp");
				push @client_args, ("--sctp");
			} elsif ($proto eq "ssl") {
				push @server_args, ("--ssl", "--ssl-key", "test-cert.pem", "--ssl-cert", "test-cert.pem");
				push @client_args, ("--ssl");
			} elsif ($proto eq "xfail") {
				$xfail = 1;
			} else {
				die "Unknown protocol $proto";
			}
		}
		server_client_test("$desc ($spec)", [@server_args], [@client_args], $code);
	}
}

# Like server_client_test, but run the test once each for each mix of TCP, UDP,
# SCTP, and SSL.
sub server_client_test_all {
	server_client_test_multi(["tcp", "udp", "sctp", "tcp ssl", "sctp ssl"], @_);
}

sub server_client_test_tcp_sctp_ssl {
	server_client_test_multi(["tcp", "sctp", "tcp ssl", "sctp ssl"], @_);
}

sub server_client_test_tcp_ssl {
	server_client_test_multi(["tcp", "tcp ssl"], @_);
}

# Set up a proxy running on $PROXY_PORT and connect a client to it. Start a
# server listening on $PORT for the convenience of having something for the
# proxy to connect to. The proxy is controlled through the variables
#   $p_pid, $p_out, and $p_in.
sub proxy_test {
	my $desc = shift;
	my $proxy_args = shift;
	my $server_args = shift;
	my $client_args = shift;
	my $code = shift;
	($p_pid, $p_out, $p_in) = ncat(($HOST, $PROXY_PORT, "-l", "--proxy-type", "http"), @$proxy_args);
	($s_pid, $s_out, $s_in) = ncat(($HOST, $PORT, "-l"), @$server_args);
	($c_pid, $c_out, $c_in) = ncat(($HOST, $PROXY_PORT), @$client_args);
	test($desc, $code);
	kill_children;
}

sub max_conns_test {
	my $desc = shift;
	my $server_args = shift;
	my $client_args = shift;
	my $count = shift;
	my @client_pids;
	my @client_outs;

	($s_pid, $s_out, $s_in) = ncat_server(@$server_args, ("--max-conns", $count));
	test $desc, sub {
		my ($i, $resp);

		# Fill the connection limit exactly.
		for ($i = 0; $i < $count; $i++) {
			my @tmp;
			($c_pid, $c_out, $c_in) = ncat_client(@$client_args);
			push @client_pids, $c_pid;
			push @client_outs, $c_out;
			syswrite($c_in, "abc\n");
			$resp = timeout_read($s_out, 2.0);
			if (!$resp) {
				syswrite($s_in, "abc\n");
				$resp = timeout_read($c_out);
			}
			$resp = "" if not defined($resp);
			$resp eq "abc\n" or die "--max-conns $count server did not accept client #" . ($i + 1);
		}
		# Try a few more times. Should be rejected.
		for (; $i < $count + 2; $i++) {
			($c_pid, $c_out, $c_in) = ncat_client(@$client_args);
			push @client_pids, $c_pid;
			push @client_outs, $c_out;
			syswrite($c_in, "abc\n");
			$resp = timeout_read($s_out, 2.0);
			if (!$resp) {
				syswrite($s_in, "abc\n");
				$resp = timeout_read($c_out);
			}
			!$resp or die "--max-conns $count server accepted client #" . ($i + 1);
		}
		# Kill one of the connected clients, which should open up a
		# space.
		{
			kill "TERM", $client_pids[0];
			while (waitpid($client_pids[0], 0) > 0) {
			}
			shift @client_pids;
			shift @client_outs;
			sleep 2;
		}
		if ($count > 0) {
			($c_pid, $c_out, $c_in) = ncat_client(@$client_args);
			push @client_pids, $c_pid;
			push @client_outs, $c_out;
			syswrite($c_in, "abc\n");
			$resp = timeout_read($s_out, 2.0);
			if (!$resp) {
				syswrite($s_in, "abc\n");
				$resp = timeout_read($c_out);
			}
			$resp = "" if not defined($resp);
			$resp eq "abc\n" or die "--max-conns $count server did not accept client #$count after freeing one space";
		}
		return 1;
	};
	kill_children;
}

sub max_conns_test_multi {
	my $specs = shift;
	my $desc = shift;
	my $server_args_ref = shift;
	my $client_args_ref = shift;
	my $count = shift;
	my $outer_xfail = $xfail;
	local $xfail;

	for my $spec (@$specs) {
		my @server_args = @$server_args_ref;
		my @client_args = @$client_args_ref;

		$xfail = $outer_xfail;
		for my $proto (split(/ /, $spec)) {
			if ($proto eq "tcp") {
				# Nothing needed.
			} elsif ($proto eq "udp") {
				push @server_args, ("--udp");
				push @client_args, ("--udp");
			} elsif ($proto eq "sctp") {
				push @server_args, ("--sctp");
				push @client_args, ("--sctp");
			} elsif ($proto eq "ssl") {
				push @server_args, ("--ssl", "--ssl-key", "test-cert.pem", "--ssl-cert", "test-cert.pem");
				push @client_args, ("--ssl");
			} elsif ($proto eq "xfail") {
				$xfail = 1;
			} else {
				die "Unknown protocol $proto";
			}
		}
		max_conns_test("$desc ($spec)", [@server_args], [@client_args], $count);
	}
}

sub max_conns_test_all {
	max_conns_test_multi(["tcp", "udp", "sctp", "tcp ssl", "sctp ssl"], @_);
}

sub max_conns_test_tcp_sctp_ssl {
	max_conns_test_multi(["tcp", "sctp", "tcp ssl", "sctp ssl"], @_);
}

sub max_conns_test_tcp_ssl {
	max_conns_test_multi(["tcp", "tcp ssl"], @_);
}

# Ignore broken pipe signals that result when trying to read from a terminated
# client.
$SIG{PIPE} = "IGNORE";
# Don't have to wait on children.
$SIG{CHLD} = "IGNORE";

# Individual tests begin here.

# Test server with no hostname or port.
($s_pid, $s_out, $s_in) = ncat("-l");
test "Server default listen address and port",
sub {
	my $resp;

	my ($c_pid, $c_out, $c_in) = ncat($HOST);
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};
kill_children;

# Test server with no hostname.
($s_pid, $s_out, $s_in) = ncat("-l", $HOST);
test "Server default port",
sub {
	my $resp;

	my ($c_pid, $c_out, $c_in) = ncat($HOST);
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};
kill_children;

# Test server with no port.
($s_pid, $s_out, $s_in) = ncat("-l", $PORT);
test "Server default listen address",
sub {
	my $resp;

	my ($c_pid, $c_out, $c_in) = ncat($HOST, $PORT);
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};
kill_children;

server_client_test "Connect success exit code",
[], ["--send-only"], sub {
	my ($pid, $code);
	local $SIG{CHLD} = sub { };

	syswrite($c_in, "abc\n");
	close($c_in);
	do {
		$pid = waitpid($c_pid, 0);
	} while ($pid > 0 && $pid != $c_pid);
	$pid == $c_pid or die;
	$code = $? >> 8;
        $code == 0 or die "Exit code was $code, not 0";
};
kill_children;

test "Connect connection refused exit code",
sub {
	my ($pid, $code);
	local $SIG{CHLD} = sub { };

	my ($c_pid, $c_out, $c_in) = ncat($HOST, $PORT, "--send-only");
	syswrite($c_in, "abc\n");
	close($c_in);
	do {
		$pid = waitpid($c_pid, 0);
	} while ($pid > 0 && $pid != $c_pid);
	$pid == $c_pid or die;
	$code = $? >> 8;
        $code == 1 or die "Exit code was $code, not 1";
};
kill_children;

test "Connect connection interrupted exit code",
sub {
	my ($pid, $code);
	local $SIG{CHLD} = sub { };
	local *SOCK;
	local *S;

	socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die;
	setsockopt(SOCK, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) or die;
	bind(SOCK, sockaddr_in($PORT, INADDR_ANY)) or die;
	listen(SOCK, 1) or die;

	my ($c_pid, $c_out, $c_in) = ncat($HOST, $PORT);

	accept(S, SOCK) or die;
	# Shut down the socket with a RST.
	setsockopt(S, SOL_SOCKET, SO_LINGER, pack("II", 1, 0)) or die;
	close(S) or die;

	do {
		$pid = waitpid($c_pid, 0);
	} while ($pid > 0 && $pid != $c_pid);
	$pid == $c_pid or die;
	$code = $? >> 8;
        $code == 1 or die "Exit code was $code, not 1";
};
kill_children;

server_client_test "Listen success exit code",
[], ["--send-only"], sub {
	my ($resp, $pid, $code);
	local $SIG{CHLD} = sub { };

	syswrite($c_in, "abc\n");
	close($c_in);
	do {
		$pid = waitpid($s_pid, 0);
	} while ($pid > 0 && $pid != $s_pid);
	$pid == $s_pid or die "$pid != $s_pid";
	$code = $? >> 8;
        $code == 0 or die "Exit code was $code, not 0";
};
kill_children;

test "Listen connection interrupted exit code",
sub {
	my ($pid, $code);
	local $SIG{CHLD} = sub { };
	local *SOCK;

	my ($s_pid, $s_out, $s_in) = ncat_server();

	socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die;
	my $addr = gethostbyname($HOST);
	connect(SOCK, sockaddr_in($PORT, $addr)) or die;
	# Shut down the socket with a RST.
	setsockopt(SOCK, SOL_SOCKET, SO_LINGER, pack("II", 1, 0)) or die;
	close(SOCK) or die;

	do {
		$pid = waitpid($s_pid, 0);
	} while ($pid > 0 && $pid != $s_pid);
	$pid == $s_pid or die;
	$code = $? >> 8;
        $code == 1 or die "Exit code was $code, not 1";
};
kill_children;

test "Program error exit code",
sub {
	my ($pid, $code);
	local $SIG{CHLD} = sub { };

	my ($c_pid, $c_out, $c_in) = ncat($HOST, $PORT, "--baffle");
	do {
		$pid = waitpid($c_pid, 0);
	} while ($pid > 0 && $pid != $c_pid);
	$pid == $c_pid or die;
	$code = $? >> 8;
        $code == 2 or die "Exit code was $code, not 2";

	my ($s_pid, $s_out, $s_in) = ncat_server("--baffle");
	do {
		$pid = waitpid($s_pid, 0);
	} while ($pid > 0 && $pid != $s_pid);
	$pid == $s_pid or die;
	$code = $? >> 8;
        $code == 2 or die "Exit code was $code, not 2";
};
kill_children;

# Test that the server closes its output stream after a client disconnects.
# This is for uses like
#   ncat -l | tar xzvf -
#   tar czf - <files> | ncat localhost --send-only
# where tar on the listening side could be any program that potentially buffers
# its input. The listener must close its standard output so the program knows
# to stop reading and process what remains in its buffer.
server_client_test_tcp_sctp_ssl "Server sends EOF after client disconnect",
[], ["--send-only"], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	close($c_in);
	$resp = timeout_read($s_out) or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
	$resp = timeout_read($s_out);
	!defined($resp) or die "Server didn't send EOF";
};
kill_children;

# Test connection persistence with --keep-open.

($s_pid, $s_out, $s_in) = ncat_server("--keep-open");
test "--keep-open",
sub {
	my $resp;

	my ($c1_pid, $c1_out, $c1_in) = ncat_client();
	syswrite($c1_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";

	my ($c2_pid, $c2_out, $c2_in) = ncat_client();
	syswrite($c2_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};
kill_children;

# Test --exec and --sh-exec.

server_client_test_all "--exec",
["--exec", "/usr/bin/perl -e \$|=1;while(<>){tr/a-z/A-Z/;print}"], [], sub {
	syswrite($c_in, "abc\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp eq "ABC\n" or die "Client received " . d($resp) . ", not " . d("ABC\n");
};

server_client_test_all "--sh-exec",
["--sh-exec", "perl -e '\$|=1;while(<>){tr/a-z/A-Z/;print}'"], [], sub {
	syswrite($c_in, "abc\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp eq "ABC\n" or die "Client received " . d($resp) . ", not " . d("ABC\n");
};

server_client_test_all "--sh-exec with -C",
["--sh-exec", "/usr/bin/perl -e '\$|=1;while(<>){tr/a-z/A-Z/;print}'", "-C"], [], sub {
	syswrite($c_in, "abc\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp eq "ABC\r\n" or die "Client received " . d($resp) . ", not " . d("ABC\r\n");
};

server_client_test_all "-C translation on input",
["-C"], ["-C"], sub {
	my $resp;
	my $expected = "\r\na\r\nb\r\n---\r\nc\r\nd\r\n---e\r\n\r\nf\r\n";

	syswrite($c_in, "\na\nb\n");
	syswrite($c_in, "---");
	syswrite($c_in, "\r\nc\r\nd\r\n");
	syswrite($c_in, "---");
	syswrite($c_in, "e\n\nf\n");
	$resp = timeout_read($s_out) or die "Read timeout";
	$resp eq $expected or die "Server received " . d($resp) . ", not " . d($expected);

	syswrite($s_in, "\na\nb\n");
	syswrite($s_in, "---");
	syswrite($s_in, "\r\nc\r\nd\r\n");
	syswrite($s_in, "---");
	syswrite($s_in, "e\n\nf\n");
	$resp = timeout_read($c_out) or die "Read timeout";
	$resp eq $expected or die "Client received " . d($resp) . ", not " . d($expected);
};
kill_children;

server_client_test_all "-C server no translation on output",
["-C"], [], sub {
	my $resp;
	my $expected = "\na\nb\n---\r\nc\r\nd\r\n";

	syswrite($c_in, "\na\nb\n");
	syswrite($c_in, "---");
	syswrite($c_in, "\r\nc\r\nd\r\n");
	$resp = timeout_read($s_out) or die "Read timeout";
	$resp eq $expected or die "Server received " . d($resp) . ", not " . d($expected);
};
kill_children;

server_client_test_tcp_sctp_ssl "-C client no translation on output",
[], ["-C"], sub {
	my $resp;
	my $expected = "\na\nb\n---\r\nc\r\nd\r\n";

	syswrite($s_in, "\na\nb\n");
	syswrite($s_in, "---");
	syswrite($s_in, "\r\nc\r\nd\r\n");
	$resp = timeout_read($c_out) or die "Read timeout";
	$resp eq $expected or die "Client received " . d($resp) . ", not " . d($expected);
};
kill_children;

# Test that both reads and writes reset the idle counter, and that the client
# properly exits after the timeout expires.
server_client_test "idle timeout",
[], ["-i", "3000"], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out) or die "Read timeout";
	sleep 2;
	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out) or die "Read timeout";
	sleep 2;
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out) or die "Read timeout";
	sleep 4;
	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out);
	!$resp or die "Client received \"$resp\" after delay of 4000 ms with idle timeout of 3000 ms."
};

# --send-only tests.

server_client_test_all "--send-only client",
[], ["--send-only"], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";

	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out);
	!$resp or die "Client received \"$resp\" in --send-only mode";
};

server_client_test_all "--send-only server",
["--send-only"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server received \"$resp\" in --send-only mode";

	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Client got \"$resp\", not \"abc\\n\"";
};

($s_pid, $s_out, $s_in) = ncat_server("--broker", "--send-only");
test "--send-only broker",
sub {
	my $resp;

	my ($c1_pid, $c1_out, $c1_in) = ncat_client();
	my ($c2_pid, $c2_out, $c2_in) = ncat_client();

	syswrite($s_in, "abc\n");
	$resp = timeout_read($c1_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Client got \"$resp\", not \"abc\\n\"";
	$resp = timeout_read($c2_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Client got \"$resp\", not \"abc\\n\"";

	syswrite($c1_in, "abc\n");
	$resp = timeout_read($c2_out);
	!$resp or die "--send-only broker relayed \"$resp\"";
};
kill_children;

# --recv-only tests.

# Note this test excludes UDP. The --recv-only UDP client never sends anything
# to the server, so the server never knows to start sending its data.
server_client_test_tcp_sctp_ssl "--recv-only client",
[], ["--recv-only"], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server received \"$resp\" from --recv-only client";

	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Client got \"$resp\", not \"abc\\n\"";
};

server_client_test_all "--recv-only server",
["--recv-only"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";

	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out);
	!$resp or die "Client received \"$resp\" from --recv-only server";
};

($s_pid, $s_out, $s_in) = ncat_server("--broker", "--recv-only");
test "--recv-only broker",
sub {
	my $resp;

	my ($c1_pid, $c1_out, $c1_in) = ncat_client();
	my ($c2_pid, $c2_out, $c2_in) = ncat_client();

	syswrite($s_in, "abc\n");
	$resp = timeout_read($c1_out);
	!$resp or die "Client received \"$resp\" from --recv-only broker";
	$resp = timeout_read($c2_out);
	!$resp or die "Client received \"$resp\" from --recv-only broker";

	syswrite($c1_in, "abc\n");
	$resp = timeout_read($c2_out);
	!$resp or die "Client received \"$resp\" from --recv-only broker";
};
kill_children;

# Source address tests.

test "Connect with -p",
sub {
	my ($pid, $code);
	local $SIG{CHLD} = sub { };
	local *SOCK;
	local *S;

	socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die;
	setsockopt(SOCK, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) or die;
	bind(SOCK, sockaddr_in($PORT, INADDR_ANY)) or die;
	listen(SOCK, 1) or die;

	my ($c_pid, $c_out, $c_in) = ncat("-p", "1234", $HOST, $PORT);

	accept(S, SOCK) or die;
	my ($port, $addr) = sockaddr_in(getpeername(S));
	$port == 1234 or die "Client connected to prosy with source port $port, not 1234";
};
kill_children;

test "Connect through HTTP proxy with -p",
sub {
	my ($pid, $code);
	local $SIG{CHLD} = sub { };
	local *SOCK;
	local *S;

	socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die;
	setsockopt(SOCK, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) or die;
	bind(SOCK, sockaddr_in($PROXY_PORT, INADDR_ANY)) or die;
	listen(SOCK, 1) or die;

	my ($c_pid, $c_out, $c_in) = ncat("--proxy-type", "http", "--proxy", "$HOST:$PROXY_PORT", "-p", "1234", $HOST, $PORT);

	accept(S, SOCK) or die;
	my ($port, $addr) = sockaddr_in(getpeername(S));
	$port == 1234 or die "Client connected to prosy with source port $port, not 1234";
};
kill_children;

test "Connect through SOCKS4 proxy with -p",
sub {
	my ($pid, $code);
	local $SIG{CHLD} = sub { };
	local *SOCK;
	local *S;

	socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die;
	setsockopt(SOCK, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) or die;
	bind(SOCK, sockaddr_in($PROXY_PORT, INADDR_ANY)) or die;
	listen(SOCK, 1) or die;

	my ($c_pid, $c_out, $c_in) = ncat("--proxy-type", "socks4", "--proxy", "$HOST:$PROXY_PORT", "-p", "1234", $HOST, $PORT);

	accept(S, SOCK) or die;
	my ($port, $addr) = sockaddr_in(getpeername(S));
	$port == 1234 or die "Client connected to prosy with source port $port, not 1234";
};
kill_children;

# HTTP proxy tests.

sub http_request {
	my ($method, $uri) = @_;
	return "$method $uri HTTP/1.0\r\n\r\n";
};

server_client_test "HTTP proxy bad request",
["--proxy-type", "http"], [], sub {
	syswrite($c_in, "bad\r\n\r\n");
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 400 or die "Expected response code 400, got $code";
};

server_client_test "HTTP CONNECT no port number",
["--proxy-type", "http"], [], sub {
	# Supposed to have a port number.
	my $req = http_request("CONNECT", "$HOST");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 400 or die "Expected response code 400, got $code";
};

server_client_test "HTTP CONNECT no port number",
["--proxy-type", "http"], [], sub {
	# Supposed to have a port number.
	my $req = http_request("CONNECT", "$HOST:");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 400 or die "Expected response code 400, got $code";
};

server_client_test "HTTP CONNECT good request",
["--proxy-type", "http"], [], sub {
	my $req = http_request("CONNECT", "$HOST:$PORT");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 200 or die "Expected response code 200, got $code";
};

server_client_test "HTTP CONNECT IPv6 address, no port number",
["--proxy-type", "http", "-6"], ["-6"], sub {
	# Supposed to have a port number.
	my $req = http_request("CONNECT", "[$IPV6_ADDR]");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 400 or die "Expected response code 400, got $code";
};

server_client_test "HTTP CONNECT IPv6 address, no port number",
["--proxy-type", "http", "-6"], ["-6"], sub {
	# Supposed to have a port number.
	my $req = http_request("CONNECT", "[$IPV6_ADDR]:");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 400 or die "Expected response code 400, got $code";
};

server_client_test "HTTP CONNECT IPv6 address, good request",
["--proxy-type", "http", "-6"], ["-6"], sub {
	my $req = http_request("CONNECT", "[$IPV6_ADDR]:$PORT");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 200 or die "Expected response code 200, got $code";
};

# Try accessing an IPv6 server with a proxy that uses -4, should fail.
proxy_test "HTTP CONNECT IPv4-only proxy",
["-4"], ["-6"], ["-4"], sub {
	my $req = http_request("CONNECT", "[$IPV6_ADDR]:$PORT");
	syswrite($c_in, $req);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 504 or die "Expected response code 504, got $code";
};

# Try accessing an IPv4 server with a proxy that uses -6, should fail.
proxy_test "HTTP CONNECT IPv6-only proxy",
["-6"], ["-4"], ["-6"], sub {
	my $req = http_request("CONNECT", "$HOST:$PORT");
	syswrite($c_in, $req);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 504 or die "Expected response code 504, got $code";
};

{
local $xfail = 1;
proxy_test "HTTP CONNECT IPv4 client, IPv6 server",
[], ["-6"], ["-4"], sub {
	my $req = http_request("CONNECT", "[$IPV6_ADDR]:$PORT");
	syswrite($c_in, $req);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 200 or die "Expected response code 200, got $code";
};
}

# Check that the proxy relays in both directions.
proxy_test "HTTP CONNECT proxy relays",
[], [], [], sub {
	my $req = http_request("CONNECT", "$HOST:$PORT");
	syswrite($c_in, $req);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 200 or die "Expected response code 200, got $code";
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out) or die "Read timeout";
	$resp eq "abc\n" or die "Proxy relayed \"$resp\", not \"abc\\n\"";
	syswrite($s_in, "def\n");
	$resp = timeout_read($c_out) or die "Read timeout";
	$resp eq "def\n" or die "Proxy relayed \"$resp\", not \"abc\\n\"";
};

# Proxy client shouldn't see the status line returned by the proxy server.
server_client_test "HTTP CONNECT client hides proxy server response",
["--proxy-type", "http"], ["--proxy", "$HOST:$PORT", "--proxy-type", "http"], sub {
	my $resp = timeout_read($c_out);
	!$resp or die "Proxy client sent " . d($resp) . " to the user stream";
};

server_client_test "HTTP CONNECT client, different Status-Line",
[], ["--proxy", "$HOST:$PORT", "--proxy-type", "http"], sub {
	my $resp;
	syswrite($s_in, "HTTP/1.1 200 Go ahead\r\n\r\nabc\n");
	$resp = timeout_read($c_out);
	if (!defined($resp)) {
		die "Client didn't recognize connection";
	} elsif ($resp ne "abc\n") {
		die "Proxy client sent " . d($resp) . " to the user stream";
	}
	return 1;
};

server_client_test "HTTP CONNECT client, server sends header",
[], ["--proxy", "$HOST:$PORT", "--proxy-type", "http"], sub {
	my $resp;
	syswrite($s_in, "HTTP/1.0 200 OK\r\nServer: ncat-test 1.2.3\r\n\r\nabc\n");
	$resp = timeout_read($c_out);
	if (!defined($resp)) {
		die "Client didn't recognize connection";
	} elsif ($resp ne "abc\n") {
		die "Proxy client sent " . d($resp) . " to the user stream";
	}
	return 1;
};

# Check that the proxy doesn't consume anything following the request when
# request and body are combined in one send. Section 3.3 of the CONNECT spec
# explicitly allows the client to send data before the connection is
# established.
proxy_test "HTTP CONNECT server doesn't consume anything after request",
[], [], [], sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\nUser-Agent: ncat-test\r\n\r\nabc\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 200 or die "Expected response code 200, got $code";

	$resp = timeout_read($s_out) or die "Read timeout";
	$resp eq "abc\n" or die "Proxy relayed \"$resp\", not \"abc\\n\"";
};

server_client_test "HTTP CONNECT overlong Request-Line",
["--proxy-type", "http"], [], sub {
	syswrite($c_in, "CONNECT " . ("A" x 24000) . ":$PORT HTTP/1.0\r\n\r\n");
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 413 or $code == 414 or die "Expected response code 413 or 414, got $code";
};

server_client_test "HTTP CONNECT overlong header",
["--proxy-type", "http"], [], sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n");
	for (my $i = 0; $i < 10000; $i++) {
		syswrite($c_in, "Header: Value\r\n");
	}
	syswrite($c_in, "\r\n");
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 413 or die "Expected response code 413, got $code";
};

server_client_test "HTTP GET hostname only",
["--proxy-type", "http"], [], sub {
	my $req = http_request("GET", "$HOST");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 400 or die "Expected response code 400, got $code";
};

server_client_test "HTTP GET path only",
["--proxy-type", "http"], [], sub {
	my $req = http_request("GET", "/");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 400 or die "Expected response code 400, got $code";
};

proxy_test "HTTP GET absolute URI",
[], [], [], sub {
	my $req = http_request("GET", "http://$HOST:$PORT/");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out) or die "Read timeout";
	$resp =~ /^GET \/ HTTP\/1\./ or die "Proxy sent \"$resp\"";
};

proxy_test "HTTP GET absolute URI, no path",
[], [], [], sub {
	my $req = http_request("GET", "http://$HOST:$PORT");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out) or die "Read timeout";
	$resp =~ /^GET \/ HTTP\/1\./ or die "Proxy sent \"$resp\"";
};

proxy_test "HTTP GET percent escape",
[], [], [], sub {
	my $req = http_request("GET", "http://$HOST:$PORT/%41");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out) or die "Read timeout";
	uri_unescape($resp) =~ /^GET \/A HTTP\/1\./ or die "Proxy sent \"$resp\"";
};

proxy_test "HTTP GET remove Connection header fields",
[], [], [], sub {
	my $req = "GET http://$HOST:$PORT/ HTTP/1.0\r\nKeep-Alive: 300\r\nOne: 1\r\nConnection: keep-alive, two, close\r\nTwo: 2\r\nThree: 3\r\n\r\n";
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out) or die "Read timeout";
	$resp = HTTP::Request->parse($resp);
	!defined($resp->header("Keep-Alive")) or die "Proxy did not remove Keep-Alive header field";
	!defined($resp->header("Two")) or die "Proxy did not remove Two header field";
	$resp->header("One") eq "1" or die "Proxy modified One header field";
	$resp->header("Three") eq "3" or die "Proxy modified Three header field";
};

proxy_test "HTTP GET combine multiple headers with the same name",
[], [], [], sub {
	my $req = "GET http://$HOST:$PORT/ HTTP/1.0\r\nConnection: keep-alive\r\nKeep-Alive: 300\r\nConnection: two\r\nOne: 1\r\nConnection: close\r\nTwo: 2\r\nThree: 3\r\n\r\n";
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out) or die "Read timeout";
	$resp = HTTP::Request->parse($resp);
	!defined($resp->header("Keep-Alive")) or die "Proxy did not remove Keep-Alive header field";
	!defined($resp->header("Two")) or die "Proxy did not remove Keep-Alive header field";
	$resp->header("One") eq "1" or die "Proxy modified One header field";
	$resp->header("Three") eq "3" or die "Proxy modified Three header field";
};

# RFC 2616 section 5.1.2: "In order to avoid request loops, a proxy MUST be able
# to recognize all of its server names, including any aliases, local variations,
# and the numeric IP address."
server_client_test "HTTP GET request loop",
["--proxy-type", "http"], [], sub {
	my $req = http_request("GET", "http://$HOST:$PORT/");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 403 or die "Expected response code 403, got $code";
};

server_client_test "HTTP GET IPv6 request loop",
["-6", "--proxy-type", "http"], ["-6"], sub {
	my $req = http_request("GET", "http://[$IPV6_ADDR]:$PORT/");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 403 or die "Expected response code 403, got $code";
};

proxy_test "HTTP HEAD absolute URI",
[], [], [], sub {
	my $req = http_request("HEAD", "http://$HOST:$PORT/");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out) or die "Read timeout";
	$resp = HTTP::Request->parse($resp);
	$resp->method eq "HEAD" or die "Proxy sent \"" . $resp->method . "\"";
};

proxy_test "HTTP POST",
[], [], [], sub {
	my $req = "POST http://$HOST:$PORT/ HTTP/1.0\r\nContent-Length: 4\r\n\r\nabc\n";
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out) or die "Read timeout";
	$resp = HTTP::Request->parse($resp);
	$resp->method eq "POST" or die "Proxy sent \"" . $resp->method . "\"";
	$resp->content eq "abc\n" or die "Proxy sent \"" . $resp->content . "\"";
};

proxy_test "HTTP POST short Content-Length",
[], [], [], sub {
	my $req = "POST http://$HOST:$PORT/ HTTP/1.0\r\nContent-Length: 2\r\n\r\nabc\n";
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out) or die "Read timeout";
	$resp = HTTP::Request->parse($resp);
	$resp->method eq "POST" or die "Proxy sent \"" . $resp->method . "\"";
	$resp->content eq "ab" or die "Proxy sent \"" . $resp->content . "\"";
};

proxy_test "HTTP POST long Content-Length",
[], [], [], sub {
	my $req = "POST http://$HOST:$PORT/ HTTP/1.0\r\nContent-Length: 10\r\n\r\nabc\n";
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out) or die "Read timeout";
	$resp = HTTP::Request->parse($resp);
	$resp->method eq "POST" or die "Proxy sent \"" . $resp->method . "\"";
	$resp->content eq "abc\n" or die "Proxy sent \"" . $resp->content . "\"";
};

proxy_test "HTTP POST chunked transfer encoding",
[], [], [], sub {
	my $req = "POST http://$HOST:$PORT/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabc\n0\r\n";
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($s_out);
	# We expect the proxy to relay the request or else die with an error
	# saying it can't do it.
	if ($resp) {
		$resp = HTTP::Request->parse($resp);
		$resp->method eq "POST" or die "Proxy sent \"" . $resp->method . "\"";
		$resp->content eq "abc\n" or die "Proxy sent \"" . $resp->content . "\"";
	} else {
		$resp = timeout_read($c_out) or die "Read timeout";
		$resp = HTTP::Response->parse($resp);
		$resp->code == 400 or $resp->code == 411 or die "Proxy returned code " . $resp->code;
	}
};

server_client_test "HTTP proxy unknown method",
["--proxy-type", "http"], [], sub {
	# Supposed to have a port number.
	my $req = http_request("NOTHING", "http://$HOST:$PORT/");
	syswrite($c_in, $req);
	close($c_in);
	my $resp = timeout_read($c_out) or die "Read timeout";
	my $code = HTTP::Response->parse($resp)->code;
	$code == 405 or die "Expected response code 405, got $code";
};

# Check that proxy auth is base64 encoded properly. 's' and '~' are 0x77 and
# 0x7E respectively, printing characters with many bits set.
for my $auth ("", "a", "a:", ":a", "user:sss", "user:ssss", "user:sssss", "user:~~~", "user:~~~~", "user:~~~~~") {
server_client_test "HTTP proxy auth base64 encoding: \"$auth\"",
[], ["--proxy", "$HOST:$PORT", "--proxy-type", "http", "--proxy-auth", $auth], sub {
	my $resp = timeout_read($s_out) or die "Read timeout";
	my $auth_header = HTTP::Response->parse($resp)->header("Proxy-Authorization") or die "Proxy client didn't send Proxy-Authorization header field";
	my ($b64_auth) = ($auth_header =~ /^Basic (.*)/) or die "No auth data in \"$auth_header\"";
	my $dec_auth = decode_base64($b64_auth);
	$auth eq $dec_auth or die "Proxy client sent \"$b64_auth\" for \"$auth\", decodes to \"$dec_auth\"";
};
}

server_client_test_multi ["tcp", "tcp ssl xfail"], "HTTP proxy server auth challenge",
["--proxy-type", "http", "--proxy-auth", "user:pass"],
[],
sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n\r\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp = HTTP::Response->parse($resp);
	my $code = $resp->code;
	$code == 407 or die "Expected response code 407, got $code";
	my $auth = $resp->header("Proxy-Authenticate");
	$auth or die "Proxy server didn't send Proxy-Authenticate header field";
};

server_client_test_multi ["tcp", "tcp ssl xfail"], "HTTP proxy server correct auth",
["--proxy-type", "http", "--proxy-auth", "user:pass"],
[],
sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n");
	syswrite($c_in, "Proxy-Authorization: Basic " . encode_base64("user:pass") . "\r\n");
	syswrite($c_in, "\r\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp = HTTP::Response->parse($resp);
	my $code = $resp->code;
	$code == 200 or die "Expected response code 200, got $code";
};

server_client_test_multi ["tcp", "tcp ssl xfail"], "HTTP proxy server wrong user",
["--proxy-type", "http", "--proxy-auth", "user:pass"],
[],
sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n");
	syswrite($c_in, "Proxy-Authorization: Basic " . encode_base64("nobody:pass") . "\r\n");
	syswrite($c_in, "\r\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp = HTTP::Response->parse($resp);
	my $code = $resp->code;
	$code == 407 or die "Expected response code 407, got $code";
};

server_client_test_multi ["tcp", "tcp ssl xfail"], "HTTP proxy server wrong pass",
["--proxy-type", "http", "--proxy-auth", "user:pass"],
[],
sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n");
	syswrite($c_in, "Proxy-Authorization: Basic " . encode_base64("user:word") . "\r\n");
	syswrite($c_in, "\r\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp = HTTP::Response->parse($resp);
	my $code = $resp->code;
	$code == 407 or die "Expected response code 407, got $code";
};

server_client_test_multi ["tcp", "tcp ssl xfail"], "HTTP proxy server correct auth, different case",
["--proxy-type", "http", "--proxy-auth", "user:pass"],
[],
sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n");
	syswrite($c_in, "pROXY-aUTHORIZATION: Basic " . encode_base64("user:pass") . "\r\n");
	syswrite($c_in, "\r\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp = HTTP::Response->parse($resp);
	my $code = $resp->code;
	$code == 200 or die "Expected response code 200, got $code";
};

# Test that header field values can be split across lines with LWS.
server_client_test_multi ["tcp", "tcp ssl xfail"], "HTTP proxy server LWS",
["--proxy-type", "http", "--proxy-auth", "user:pass"],
[],
sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n");
	syswrite($c_in, "Proxy-Authorization:\t  Basic  \r\n\t  \n dXNlcjpwYXNz\r\n");
	syswrite($c_in, "\r\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp = HTTP::Response->parse($resp);
	my $code = $resp->code;
	$code == 200 or die "Expected response code 200, got $code";
};

server_client_test_multi ["tcp", "tcp ssl xfail"], "HTTP proxy server LWS",
["--proxy-type", "http", "--proxy-auth", "user:pass"],
[],
sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n");
	syswrite($c_in, "Proxy-Authorization: Basic\r\n dXNlcjpwYXNz\r\n");
	syswrite($c_in, "\r\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp = HTTP::Response->parse($resp);
	my $code = $resp->code;
	$code == 200 or die "Expected response code 200, got $code";
};

server_client_test_multi ["tcp", "tcp ssl xfail"], "HTTP proxy server no auth",
["--proxy-type", "http", "--proxy-auth", "user:pass"],
[],
sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n");
	syswrite($c_in, "Proxy-Authorization: \r\n");
	syswrite($c_in, "\r\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp = HTTP::Response->parse($resp);
	my $code = $resp->code;
	$code != 200 or die "Got unexpected 200 response";
};

server_client_test_multi ["tcp", "tcp ssl xfail"], "HTTP proxy server broken auth",
["--proxy-type", "http", "--proxy-auth", "user:pass"],
[],
sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n");
	syswrite($c_in, "Proxy-Authorization: French fries\r\n");
	syswrite($c_in, "\r\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp = HTTP::Response->parse($resp);
	my $code = $resp->code;
	$code != 200 or die "Got unexpected 200 response";
};

server_client_test_multi ["tcp", "tcp ssl xfail"], "HTTP proxy server extra auth",
["--proxy-type", "http", "--proxy-auth", "user:pass"],
[],
sub {
	syswrite($c_in, "CONNECT $HOST:$PORT HTTP/1.0\r\n");
	syswrite($c_in, "Proxy-Authorization: Basic " . encode_base64("user:pass") . " extra\r\n");
	syswrite($c_in, "\r\n");
	my $resp = timeout_read($c_out) or die "Read timeout";
	$resp = HTTP::Response->parse($resp);
	my $code = $resp->code;
	$code != 200 or die "Got unexpected 200 response";
};

# Allow and deny list tests.

server_client_test_all "Allow localhost (IPv4 address)",
["--allow", "127.0.0.1"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};

server_client_test_all "Allow localhost (host name)",
["--allow", "localhost"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};

# Anyone not allowed is denied.
server_client_test_all "Allow non-localhost",
["--allow", "1.2.3.4"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server did not reject host not in allow list";
};

# --allow options should accumulate.
server_client_test_all "--allow options accumulate",
["--allow", "127.0.0.1", "--allow", "1.2.3.4"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};

server_client_test_all "Deny localhost (IPv4 address)",
["--deny", "127.0.0.1"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server did not reject host in deny list";
};

server_client_test_all "Deny localhost (host name)",
["--deny", "localhost"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server did not reject host in deny list";
};

# Anyone not denied is allowed.
server_client_test_all "Deny non-localhost",
["--deny", "1.2.3.4"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};

# --deny options should accumulate.
server_client_test_all "--deny options accumulate",
["--deny", "127.0.0.1", "--deny", "1.2.3.4"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server did not reject host in deny list";
};

# If a host is both allowed and denied, denial takes precedence.
server_client_test_all "Allow and deny",
["--allow", "127.0.0.1", "--deny", "127.0.0.1"], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server did not reject host in deny list";
};

# Test that --allowfile and --denyfile handle blank lines and more than one
# specification per line.
for my $contents (
"1.2.3.4

localhost",
"1.2.3.4 localhost"
) {
my ($fh, $filename) = tempfile("ncat-test-XXXXX", SUFFIX => ".txt");
print $fh $contents;
server_client_test_all "--allowfile",
["--allowfile", $filename], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};
server_client_test_all "--denyfile",
["--denyfile", $filename], [], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server did not reject host in --denyfile list";
};
unlink $filename;
}

# Test --ssl sending.
server_client_test "SSL server relays",
["--ssl", "--ssl-key", "test-cert.pem", "--ssl-cert", "test-cert.pem"], ["--ssl"], sub {
	my $resp;

	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";

	syswrite($s_in, "abc\n");
	$resp = timeout_read($c_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Client got \"$resp\", not \"abc\\n\"";
};

# Test that an SSL server gracefully handles non-SSL connections.
($s_pid, $s_out, $s_in) = ncat_server("--ssl", "--ssl-key", "test-cert.pem", "--ssl-cert", "test-cert.pem");
test "SSL server handles non-SSL connections",
sub {
	my $resp;

	my ($c1_pid, $c1_out, $c1_in) = ncat_client();
	syswrite($c1_in, "abc\n");
	kill "TERM", $c1_pid;
	waitpid $c1_pid, 0;

	my ($c2_pid, $c2_out, $c2_in) = ncat_client("--ssl");
	syswrite($c2_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
	kill "TERM", $c2_pid;
	waitpid $c2_pid, 0;
};
kill_children;

($s_pid, $s_out, $s_in) = ncat_server("--ssl", "--ssl-key", "test-cert.pem", "--ssl-cert", "test-cert.pem");
test "SSL verification, correct domain name",
sub {
	my $resp;

	($c_pid, $c_out, $c_in) = ncat($HOST, $PORT, "--ssl-verify", "--ssl-trustfile", "test-cert.pem");
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	$resp or die "Read timeout";
	$resp eq "abc\n" or die "Server got \"$resp\", not \"abc\\n\"";
};
kill_children;

($s_pid, $s_out, $s_in) = ncat_server("--ssl", "--ssl-key", "test-cert.pem", "--ssl-cert", "test-cert.pem");
test "SSL verification, wrong domain name",
sub {
	my $resp;

	# Use the IPv6 address as an alternate name that doesn't match the one
	# on the certificate.
	($c_pid, $c_out, $c_in) = ncat($IPV6_ADDR, $PORT, "-6", "--ssl-verify", "--ssl-trustfile", "test-cert.pem");
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server got \"$resp\" when verification should have failed";
};
kill_children;

($s_pid, $s_out, $s_in) = ncat_server("--ssl");
test "SSL verification, no server cert",
sub {
	my $resp;

	($c_pid, $c_out, $c_in) = ncat($HOST, $PORT, "--ssl-verify", "--ssl-trustfile", "test-cert.pem");
	syswrite($c_in, "abc\n");
	$resp = timeout_read($s_out);
	!$resp or die "Server got \"$resp\" when verification should have failed";
};
kill_children;

# Test --max-conns.
for my $count (0, 1, 10) {
	max_conns_test_tcp_sctp_ssl("--max-conns $count --keep-open", ["--keep-open"], [], $count);
}

for my $count (0, 1, 10) {
	max_conns_test_tcp_ssl("--max-conns $count --broker", ["--broker"], [], $count);
}

max_conns_test_all("--max-conns 0 with exec", ["--exec", "/bin/cat"], [], 0);
for my $count (1, 10) {
	max_conns_test_multi(["tcp", "sctp", "udp xfail", "tcp ssl", "sctp ssl"],
		"--max-conns $count with exec", ["--exec", "/bin/cat"], [], $count);
}

print "$num_expected_failures expected failures.\n" if $num_expected_failures > 0;
print "$num_unexpected_passes unexpected passes.\n" if $num_unexpected_passes > 0;
print "$num_failures unexpected failures.\n";
print "$num_tests tests total.\n";

if ($num_failures + $num_unexpected_passes == 0) {
	exit 0;
} else {
	exit 1;
}
