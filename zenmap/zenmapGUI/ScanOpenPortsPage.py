#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2009 Insecure.Com LLC. Nmap is    *
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
# * listed in the included COPYING.OpenSSL file, and distribute linked      *
# * combinations including the two. You must obey the GNU GPL in all        *
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

import gtk

from zenmapGUI.higwidgets.higboxes import HIGVBox, HIGHBox
from zenmapGUI.higwidgets.higtables import HIGTable

from zenmapCore.UmitLogging import log
import zenmapCore.I18N

class ScanOpenPortsPage(gtk.ScrolledWindow):
    def __init__(self):
        gtk.ScrolledWindow.__init__(self)
        self.set_policy(gtk.POLICY_AUTOMATIC,gtk.POLICY_AUTOMATIC)
        
        self.__create_widgets()
        
        self.add_with_viewport(self.host)

    def __create_widgets(self):
        self.host = HostOpenPorts()

class HostOpenPorts(HIGVBox):
    def __init__(self):
        HIGVBox.__init__(self)
        
        self._create_widgets()
        self._set_port_list()
        self._set_host_list()
        self._pack_widgets()

    def _create_widgets(self):
        # Ports view
        self.port_columns = {}
        self.port_list = gtk.ListStore(str, str, int, str, str, str, str)
        self.port_tree = gtk.TreeStore(str, str, int, str, str, str, str)
        
        self.port_view = gtk.TreeView(self.port_list)
        
        self.cell_icon = gtk.CellRendererPixbuf()
        self.cell_port = gtk.CellRendererText()
        
        self.port_columns['hostname'] = gtk.TreeViewColumn(_('Host'))
        self.port_columns['icon'] = gtk.TreeViewColumn('')
        self.port_columns['port_number'] = gtk.TreeViewColumn(_('Port'))
        self.port_columns['protocol'] = gtk.TreeViewColumn(_('Protocol'))
        self.port_columns['state'] = gtk.TreeViewColumn(_('State'))
        self.port_columns['service'] = gtk.TreeViewColumn(_('Service'))
        self.port_columns['version'] = gtk.TreeViewColumn(_('Version'))

        # Host services view
        self.host_columns = {}
        self.host_list = gtk.ListStore(str, str, str, int, str, str, str)
        self.host_tree = gtk.TreeStore(str, str, str, int, str, str, str)
        
        self.host_view = gtk.TreeView(self.host_list)
        
        self.cell_host_icon = gtk.CellRendererPixbuf()
        self.cell_host = gtk.CellRendererText()
        
        self.host_columns['service'] = gtk.TreeViewColumn(_('Service'))
        self.host_columns['hostname'] = gtk.TreeViewColumn(_('Hostname'))
        self.host_columns['icon'] = gtk.TreeViewColumn('')
        self.host_columns['protocol'] = gtk.TreeViewColumn(_('Protocol'))
        self.host_columns['port_number'] = gtk.TreeViewColumn(_('Port'))
        self.host_columns['state'] = gtk.TreeViewColumn(_('State'))
        self.host_columns['version'] = gtk.TreeViewColumn(_('Version'))
        
        self.scroll_ports_hosts = gtk.ScrolledWindow()

    def _set_host_list(self):
        self.host_view.set_enable_search(True)
        self.host_view.set_search_column(2)
        
        selection = self.host_view.get_selection()
        selection.set_mode(gtk.SELECTION_MULTIPLE)

        columns = ["service", "icon", "hostname", "port_number",
                   "protocol", "state", "version"]
        
        for c in columns:
            self.host_view.append_column(self.host_columns[c])
            self.host_columns[c].set_reorderable(True)
            self.host_columns[c].set_resizable(True)

        self.host_columns['service'].connect('clicked', self.set_host_search_cb, 0)
        self.host_columns['icon'].connect('clicked', self.set_host_search_cb, 5)
        self.host_columns['hostname'].connect('clicked', self.set_host_search_cb, 2)
        self.host_columns['port_number'].connect('clicked', self.set_host_search_cb, 3)
        self.host_columns['protocol'].connect('clicked', self.set_host_search_cb, 4)
        self.host_columns['state'].connect('clicked', self.set_host_search_cb, 5)
        self.host_columns['version'].connect('clicked', self.set_host_search_cb, 6)

        self.host_columns['service'].set_sort_column_id(0)
        self.host_columns['icon'].set_min_width(35)
        self.host_columns['icon'].set_sort_column_id(5)
        self.host_columns['hostname'].set_sort_column_id(2)
        self.host_columns['port_number'].set_sort_column_id(3)
        self.host_columns['protocol'].set_sort_column_id(4)
        self.host_columns['state'].set_sort_column_id(5)
        self.host_columns['version'].set_sort_column_id(6)

        self.host_columns['service'].pack_start(self.cell_port, True)
        self.host_columns['icon'].pack_start(self.cell_host_icon, True)
        self.host_columns['hostname'].pack_start(self.cell_port, True)
        self.host_columns['port_number'].pack_start(self.cell_port, True)
        self.host_columns['protocol'].pack_start(self.cell_port, True)
        self.host_columns['version'].pack_start(self.cell_port, True)
        self.host_columns['state'].pack_start(self.cell_port, True)
        
        self.host_columns['service'].set_attributes(self.cell_port, text=0)
        self.host_columns['icon'].set_attributes(self.cell_host_icon, stock_id=1)
        self.host_columns['hostname'].set_attributes(self.cell_port, text=2)
        self.host_columns['port_number'].set_attributes(self.cell_port, text=3)
        self.host_columns['protocol'].set_attributes(self.cell_port, text=4)
        self.host_columns['state'].set_attributes(self.cell_port, text=5)
        self.host_columns['version'].set_attributes(self.cell_port, text=6)
        
        self.host_columns['service'].set_visible(False)
        
        self.scroll_ports_hosts.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
    
    def _set_port_list(self):
        self.port_view.set_enable_search(True)
        self.port_view.set_search_column(3)
        
        selection = self.port_view.get_selection()
        selection.set_mode(gtk.SELECTION_MULTIPLE)
        
        self.port_view.append_column(self.port_columns['hostname'])
        self.port_view.append_column(self.port_columns['icon'])
        self.port_view.append_column(self.port_columns['port_number'])
        self.port_view.append_column(self.port_columns['protocol'])
        self.port_view.append_column(self.port_columns['state'])
        self.port_view.append_column(self.port_columns['service'])
        self.port_view.append_column(self.port_columns['version'])
        
        for k in self.port_columns:
            self.port_columns[k].set_reorderable(True)
            self.port_columns[k].set_resizable(True)


        self.port_columns['icon'].set_min_width(35)

        self.port_columns['hostname'].connect('clicked', self.set_search_cb, 0)
        self.port_columns['icon'].connect('clicked', self.set_search_cb, 4)
        self.port_columns['port_number'].connect('clicked', self.set_search_cb,
                                                 2)
        self.port_columns['protocol'].connect('clicked', self.set_search_cb, 3)
        self.port_columns['state'].connect('clicked', self.set_search_cb, 4)
        self.port_columns['service'].connect('clicked', self.set_search_cb, 5)
        self.port_columns['version'].connect('clicked', self.set_search_cb, 6)
        
        self.port_columns['hostname'].set_sort_column_id(0)
        self.port_columns['icon'].set_sort_column_id(4)
        self.port_columns['port_number'].set_sort_column_id(2)
        self.port_columns['protocol'].set_sort_column_id(3)
        self.port_columns['state'].set_sort_column_id(4)
        self.port_columns['service'].set_sort_column_id(5)
        self.port_columns['version'].set_sort_column_id(6)
        
        self.port_columns['hostname'].pack_start(self.cell_port, True)
        self.port_columns['icon'].pack_start(self.cell_icon, True)
        self.port_columns['port_number'].pack_start(self.cell_port, True)
        self.port_columns['protocol'].pack_start(self.cell_port, True)
        self.port_columns['service'].pack_start(self.cell_port, True)
        self.port_columns['version'].pack_start(self.cell_port, True)
        self.port_columns['state'].pack_start(self.cell_port, True)
        
        self.port_columns['hostname'].set_attributes(self.cell_port, text=0)
        self.port_columns['icon'].set_attributes(self.cell_icon, stock_id=1)
        self.port_columns['port_number'].set_attributes(self.cell_port, text=2)
        self.port_columns['protocol'].set_attributes(self.cell_port, text=3)
        self.port_columns['state'].set_attributes(self.cell_port, text=4)
        self.port_columns['service'].set_attributes(self.cell_port, text=5)
        self.port_columns['version'].set_attributes(self.cell_port, text=6)
        
        self.port_columns['hostname'].set_visible(False)
        
        self.scroll_ports_hosts.set_policy(gtk.POLICY_AUTOMATIC,\
                                          gtk.POLICY_AUTOMATIC)

    def port_mode(self):
        child = self.scroll_ports_hosts.get_child()
        if id(child) != id(self.port_view):
            if child is not None:
                self.scroll_ports_hosts.remove(child)
            self.scroll_ports_hosts.add(self.port_view)
            self.port_view.show_all()
            self.host_view.hide()

    def host_mode(self):
        child = self.scroll_ports_hosts.get_child()
        if id(child) != id(self.host_view):
            if child is not None:
                self.scroll_ports_hosts.remove(child)
            self.scroll_ports_hosts.add(self.host_view)
            self.host_view.show_all()
            self.port_view.hide()

    def set_ports(self, ports):
        self.clear_port_list()
        
        for p in ports:
            self.port_list.append(p)

    def set_hosts(self, hosts):
        self.clear_host_list()

        for h in hosts:
            self.host_list.append(h)
    
    def add_port(self, port_info):
        log.debug(">>> Add Port: %s" % port_info)
        self.port_list.append([""] + port_info)

    def add_host(self, host_info):
        log.debug(">>> Add Host: %s" % host_info)
        self.host_list.append([""] + host_info)
    
    def switch_port_to_list_store(self):
        if self.port_view.get_model() != self.port_list:
            self.port_view.set_model(self.port_list)
            self.port_columns['hostname'].set_visible(False)
    
    def switch_port_to_tree_store(self):
        if self.port_view.get_model() != self.port_tree:
            self.port_view.set_model(self.port_tree)
            self.port_columns['hostname'].set_visible(True)
    
    def switch_host_to_list_store(self):
        if self.host_view.get_model() != self.host_list:
            self.host_view.set_model(self.host_list)
            self.host_columns['service'].set_visible(False)
    
    def switch_host_to_tree_store(self):
        if self.host_view.get_model() != self.host_tree:
            self.host_view.set_model(self.host_tree)
            self.host_columns['service'].set_visible(True)

    def set_search_cb(self, widget, column_id):
        self.port_view.set_search_column(column_id)

    def set_host_search_cb(self, widget, column_id):
        self.host_view.set_search_column(column_id)
    
    def _pack_widgets(self):
        self.scroll_ports_hosts.add(self.port_view)
        self._pack_expand_fill(self.scroll_ports_hosts)

    def clear_port_list(self):
        for i in range(len(self.port_list)):
            iter = self.port_list.get_iter_root()
            del(self.port_list[iter])
            
    def clear_host_list(self):
        for i in range(len(self.host_list)):
            iter = self.host_list.get_iter_root()
            del(self.host_list[iter])

    def clear_port_tree(self):
        for i in range(len(self.port_tree)):
            iter = self.port_tree.get_iter_root()
            del(self.port_tree[iter])

    def clear_host_tree(self):
        for i in range(len(self.host_tree)):
            iter = self.host_tree.get_iter_root()
            del(self.host_tree[iter])

if __name__ == "__main__":
    w = gtk.Window()
    h = HostOpenPorts()
    w.add(h)
    w.show_all()

    gtk.main()
