import time
import gi
import os
import urllib.parse
from func.scan import ScanApi

gi.require_version('Gtk', '3.0')

from gi.repository import Gtk, Gdk

whatis = lambda obj: print(type(obj), "\n\t" + "\n\t".join(dir(obj)))

print(time.time())

from configparser import ConfigParser

cfg = ConfigParser()
cfg.read('config.ini')


class MainWindow:

    def __init__(self):
        self.glade_file = "ui/UI.glade"
        self.builder = Gtk.Builder()
        self.builder.add_from_file(self.glade_file)
        self.builder.connect_signals(self)
        self.window = self.builder.get_object("main_window")
        self.edit_singe_scan = self.builder.get_object("Edit_Single_Scan")
        self.edit_singe_scan.drag_dest_unset()
        self.Gtk_Text_View = self.builder.get_object("gtk_text_view")
        self.Gtk_Text_View.drag_dest_unset()
        self.TreeView_Target = self.builder.get_object("tree_view_target")
        self.label_drop_file = self.builder.get_object("label_drop_file")
        enforce_target = Gtk.TargetEntry.new('text/plain', Gtk.TargetFlags(4), 129)
        self.label_drop_file.drag_dest_set(Gtk.DestDefaults.ALL, [enforce_target], Gdk.DragAction.COPY)

        # add column
        renderer = Gtk.CellRendererText()
        for i, column in enumerate(self.TreeView_Target.get_columns()):
            column.pack_start(renderer, False)
            column.add_attribute(renderer, "text", i)

        self.list_store_target = self.builder.get_object("list_store_target")
        self.ComboBox_Text_Host = self.builder.get_object("ComboBox_Text_Host")
        for scanner in cfg.sections():
            self.ComboBox_Text_Host.append_text(scanner)

        self.ComboBox_Text_Host.set_active(0)
        self.scan = ScanApi(cfg.get(self.ComboBox_Text_Host.get_active_text(), "host"),
                            cfg.get(self.ComboBox_Text_Host.get_active_text(), "key"))
        self.ComboBox_Text_Speed = self.builder.get_object("ComboBox_Text_Speed")
        self.Edit_Description = self.builder.get_object("Edit_Description")
        self.Enable_Proxy = self.builder.get_object("Enable_Proxy")
        self.Proxy_Host = self.builder.get_object("Proxy_Host")
        self.Proxy_Port = self.builder.get_object("Proxy_Port")
        self.Menu = self.builder.get_object("Menu")
        self.window.show()

    def on_refresh_target_activate(self, object, data=None):
        print("刷新目标信息")
        self.scan.get_target_info(self.list_store_target)

    def on_main_window_destroy(self, object, data=None):
        self.useless_func()
        print("quit with cancel")
        Gtk.main_quit()

    def on_gtk_quit_activate(self, menuitem, data=None):
        self.useless_func()
        print("quit from menu")
        Gtk.main_quit()

    def on_button_single_scan_clicked(self, widget, data=None):
        self.useless_func()
        print("单个扫描")
        print(self.edit_singe_scan.get_text())
        address = self.edit_singe_scan.get_text()
        if not address.__len__():
            return False
        if address[0:4] != "http":
            address = "http://" + address
        target_id = self.scan.add_target_to_scan(address=address, description=self.Edit_Description.get_text())
        if self.Enable_Proxy.get_active():
            print("Proxy")
            self.scan.set_proxy(target_id=target_id, ip=self.Proxy_Port.get_text(), port=self.Proxy_Port.get_text())
        self.scan.set_speed(target_id=target_id, speed=self.ComboBox_Text_Speed.get_active_text())
        self.scan.start_scan(target_id=target_id)
        # self.on_refresh_target_activate(widget)

    def on_button_batch_scan_clicked(self, widget, data=None):
        self.useless_func()
        print("批量扫描")
        text_buffer = self.Gtk_Text_View.get_buffer()
        text_targets_list = text_buffer.get_text(text_buffer.get_start_iter(), text_buffer.get_end_iter(), False)
        for address in text_targets_list.split(os.linesep):
            if not address.__len__():
                return False
            if address[0:4] != "http":
                address = "http://" + address
            target_id = self.scan.add_target_to_scan(address=address, description=self.Edit_Description.get_text())
            if self.Enable_Proxy.get_active():
                print("Proxy")
                self.scan.set_proxy(target_id=target_id, ip=self.Proxy_Port.get_text(), port=self.Proxy_Port.get_text())
            self.scan.set_speed(target_id=target_id, speed=self.ComboBox_Text_Speed.get_active_text())
            self.scan.start_scan(target_id=target_id)
        self.on_refresh_target_activate(widget)

    def on_button_clear_list_clicked(self, object, data=None):
        self.list_store_target.clear()

    def on_combobox_text_host_changed(self, combo, data=None):
        api_host, api_key = [cfg.get(combo.get_active_text(), "host"), cfg.get(combo.get_active_text(), "key")]
        self.scan = ScanApi(api_host, api_key)
        self.useless_func()
        return api_host, api_key

    def on_batch_del_clicked(self, widget, data=None):
        print("批量删除")
        model = self.TreeView_Target.get_model()
        for row in model:
            print(row[1])
            self.scan.del_target(target_id=row[1])
        self.on_refresh_target_activate(widget)

    def on_tree_view_target_button_press_event(self, widget, event=None):
        if event.button == 3:  # right click
            self.Menu.popup(None, widget, None, None, event.button, event.time)

    def on_delete_target_activate(self, widget, event=None):
        selection = self.TreeView_Target.get_selection()
        (model, path_list) = selection.get_selected_rows()
        for path in path_list:
            tree_iter = model.get_iter(path)
            value = model.get_value(tree_iter, 1)
            self.scan.del_target(value)
        self.on_refresh_target_activate(widget)

    def on_label_drop_file_drag_data_received(self, widget, context, x, y, sel, target_type, timestamp):
        file_path = urllib.parse.unquote(sel.get_text()).replace(os.linesep, "")
        print(file_path)
        text_buffer = self.Gtk_Text_View.get_buffer()
        with open(file=file_path[7:], mode="r") as f:
            text_buffer.set_text(f.read())
            self.Gtk_Text_View.set_buffer(text_buffer)

    def main(self):
        self.useless_func()
        Gtk.main()

    def useless_func(self):
        pass
