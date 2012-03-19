#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
# * also a registered trademark of Insecure.Com LLC.  This program is free  *
# * software; you may redistribute and/or modify it under the terms of the  *
# * GNU General Public License as published by the Free Software            *
# * Foundation; Version 2 with the clarifications and exceptions described  *
# * below.  This guarantees your right to use, modify, and redistribute     *
# * this software under certain conditions.  If you wish to embed Nmap      *
# * technology into proprietary software, we sell alternative licenses      *
# * (contact sales@insecure.com).  Dozens of software vendors already       *
# * license Nmap technology such as host discovery, port scanning, OS       *
# * detection, and version detection.                                       *
# *                                                                         *
# * Note that the GPL places important restrictions on "derived works", yet *
# * it does not provide a detailed definition of that term.  To avoid       *
# * misunderstandings, we consider an application to constitute a           *
# * "derivative work" for the purpose of this license if it does any of the *
# * following:                                                              *
# * o Integrates source code from Nmap                                      *
# * o Reads or includes Nmap copyrighted data files, such as                *
# *   nmap-os-db or nmap-service-probes.                                    *
# * o Executes Nmap and parses the results (as opposed to typical shell or  *
# *   execution-menu apps, which simply display raw Nmap output and so are  *
# *   not derivative works.)                                                *
# * o Integrates/includes/aggregates Nmap into a proprietary executable     *
# *   installer, such as those produced by InstallShield.                   *
# * o Links to a library or executes a program that does any of the above   *
# *                                                                         *
# * The term "Nmap" should be taken to also include any portions or derived *
# * works of Nmap.  This list is not exclusive, but is meant to clarify our *
# * interpretation of derived works with some common examples.  Our         *
# * interpretation applies only to Nmap--we don't speak for other people's  *
# * GPL works.                                                              *
# *                                                                         *
# * If you have any questions about the GPL licensing restrictions on using *
# * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
# * we also offer alternative license to integrate Nmap into proprietary    *
# * applications and appliances.  These contracts have been sold to dozens  *
# * of software vendors, and generally include a perpetual license as well  *
# * as providing for priority support and updates as well as helping to     *
# * fund the continued development of Nmap technology.  Please email        *
# * sales@insecure.com for further information.                             *
# *                                                                         *
# * As a special exception to the GPL terms, Insecure.Com LLC grants        *
# * permission to link the code of this program with any version of the     *
# * OpenSSL library which is distributed under a license identical to that  *
# * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
# * linked combinations including the two. You must obey the GNU GPL in all *
# * respects for all of the code used other than OpenSSL.  If you modify    *
# * this file, you may extend this exception to your version of the file,   *
# * but you are not obligated to do so.                                     *
# *                                                                         *
# * If you received these files with a written license agreement or         *
# * contract stating terms other than the terms above, then that            *
# * alternative license agreement takes precedence over these comments.     *
# *                                                                         *
# * Source is provided to this software because we believe users have a     *
# * right to know exactly what a program is going to do before they run it. *
# * This also allows you to audit the software for security holes (none     *
# * have been found so far).                                                *
# *                                                                         *
# * Source code also allows you to port Nmap to new platforms, fix bugs,    *
# * and add new features.  You are highly encouraged to send your changes   *
# * to nmap-dev@insecure.org for possible incorporation into the main       *
# * distribution.  By sending these changes to Fyodor or one of the         *
# * Insecure.Org development mailing lists, it is assumed that you are      *
# * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
# * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
# * will always be available Open Source, but this is important because the *
# * inability to relicense code has caused devastating problems for other   *
# * Free Software projects (such as KDE and NASM).  We also occasionally    *
# * relicense the code to third parties as discussed above.  If you wish to *
# * specify special license conditions of your contributions, just say so   *
# * when you send them.                                                     *
# *                                                                         *
# * This program is distributed in the hope that it will be useful, but     *
# * WITHOUT ANY WARRANTY; without even the implied warranty of              *
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
# * General Public License v2.0 for more details at                         *
# * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
# * included with Nmap.                                                     *
# *                                                                         *
# ***************************************************************************/

import sys
import gtk
import gobject
import urllib2
import webbrowser

from zenmapGUI.higwidgets.higdialogs import HIGAlertDialog
from zenmapGUI.higwidgets.higlabels import HIGSectionLabel, HIGHintSectionLabel
from zenmapGUI.higwidgets.higtables import HIGTable
from zenmapGUI.higwidgets.higwindows import HIGWindow
from zenmapGUI.higwidgets.higboxes import HIGHBox, HIGVBox

from zenmapCore.Name import APP_DISPLAY_NAME
from zenmapCore.BugRegister import BugRegister
import zenmapCore.I18N

class CrashReport(HIGWindow):
    def __init__(self, summary, description):
        HIGWindow.__init__(self)
        gtk.Window.__init__(self)
        self.set_title(_('Crash Report'))
        self.set_position(gtk.WIN_POS_CENTER_ALWAYS)

        self.response_id = False

        self._create_widgets()
        self._pack_widgets()
        self._connect_widgets()

        self.summary = summary
        self.description = "\n----\n" + description

    def _create_widgets(self):
        self.vbox = HIGVBox()
        self.button_box = gtk.HButtonBox()

        self.email_label = gtk.Label(_("""\
An email address is optional. Sometimes we use it to get more information. If \
you provide an email address your report will be marked private so only \
project developers can read it.\
"""))
        self.email_entry = gtk.Entry()

        self.summary_entry = gtk.Entry()

        self.description_label = gtk.Label(_("\
What were you doing when the crash happened?\
"))
        self.description_scrolled = gtk.ScrolledWindow()
        self.description_text = gtk.TextView()

        self.bug_text = gtk.Label(_("""\
An unhandled exception has crashed Zenmap. This dialog allows you to tell us \
what you did to cause the crash and help us to fix it. Submitting the report \
will open a description of the new bug at the bug tracker. Feel free to edit \
the report to remove any identifying information such as your home directory.\
"""))

        self.btn_ok = gtk.Button(stock=gtk.STOCK_OK)
        self.btn_cancel = gtk.Button(stock=gtk.STOCK_CANCEL)

        self.hbox = HIGHBox()
        self.table = HIGTable()

    def _pack_widgets(self):
        self.description_label.set_line_wrap(True)
        self.description_label.set_alignment(0.0, 0.5)
        self.description_scrolled.add(self.description_text)
        self.description_scrolled.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        self.description_scrolled.set_size_request(400, 150)
        self.description_text.set_wrap_mode(gtk.WRAP_WORD)

        self.email_label.set_line_wrap(True)
        self.email_label.set_alignment(0.0, 0.5)

        self.bug_text.set_line_wrap(True)

        self.hbox.set_border_width(12)
        self.vbox.set_border_width(6)

        self.table.attach_label(gtk.Label(_("Summary")), 0, 1, 0, 1)
        self.table.attach_entry(self.summary_entry, 1, 2, 0, 1)

        self.table.attach_entry(self.description_label, 0, 2, 1, 2)
        self.table.attach_entry(self.description_scrolled, 0, 2, 2, 3)

        self.table.attach(self.email_label, 0, 2, 3, 4)
        self.table.attach_label(gtk.Label(_("Email")), 0, 1, 4, 5)
        self.table.attach_entry(self.email_entry, 1, 2, 4, 5)

        self.hbox._pack_expand_fill(self.bug_text)

        self.button_box.set_layout(gtk.BUTTONBOX_END)
        self.button_box.pack_start(self.btn_ok)
        self.button_box.pack_start(self.btn_cancel)

        self.vbox._pack_noexpand_nofill(self.hbox)
        self.vbox._pack_expand_fill(self.table)
        self.vbox._pack_noexpand_nofill(self.button_box)
        self.add(self.vbox)

    def _connect_widgets(self):
        self.btn_ok.connect("clicked", self.send_report)
        self.btn_cancel.connect("clicked", self.close)
        self.connect("delete-event", self.close)

    def send_report(self, widget):
        bug_register = BugRegister()
        description_text = self.description
        private = False
        if self.email != "":
            description_text += "\n\n" + self.email
            private = True
        report_url = bug_register.get_report_url(self.summary,
            description_text, private = private)

        # First we try reporting the bug with a web browser because that gives
        # better feedback on what happened. If that doesn't work try with
        # urllib2.
        try:
            webbrowser.open(report_url)
        except webbrowser.Error:
            try:
                urllib2.urlopen(report_url)
                ok_dialog = HIGAlertDialog(type=gtk.MESSAGE_INFO,
                    message_format=_("Bug reported"),
                    secondary_text=_("The bug was successfully reported."))
                ok_dialog.run()
                ok_dialog.destroy()
            except urllib2.URLError, e:
                cancel_dialog = HIGAlertDialog(type=gtk.MESSAGE_ERROR,
                    message_format=_("Bug not reported"),
                    secondary_text=_("This error occurred while trying to report the bug:\n\n" + str(e)))
                cancel_dialog.run()
                cancel_dialog.destroy()

        self.close()

    def close(self, widget=None, event=None):
        self.destroy()
        gtk.main_quit()
        sys.exit(0)

    def get_summary(self):
        return self.summary_entry.get_text()

    def set_summary(self, summary):
        summary = summary.decode("UTF-8", "replace")
        self.summary_entry.set_text(summary)

    def get_description(self):
        buff = self.description_text.get_buffer()
        return buff.get_text(buff.get_start_iter(), buff.get_end_iter())

    def set_description(self, description):
        description = description.decode("UTF-8", "replace")
        self.description_text.get_buffer().set_text(description)

    def get_email(self):
        return self.email_entry.get_text()

    def set_email(self, email):
        self.email_entry.set_text(email)

    def run_unblocked(self):
        if not self.modal:
            self.set_modal(True)
        self.show_all()

    summary = property(get_summary, set_summary)
    description = property(get_description, set_description)
    email = property(get_email, set_email)


if __name__ == "__main__":
    c = CrashReport("Sumariu", "Descricao")
    c.show_all()
    c.connect("delete-event", lambda x, y: gtk.main_quit())

    gtk.main()
