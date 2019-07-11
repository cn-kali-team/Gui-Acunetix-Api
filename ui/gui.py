import gi
from configparser import ConfigParser
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk
import os
import urllib.parse
from func.scan import ScanApi, VulnerabilitiesApi
from func.verify import SqlMapApi
import func.report
from concurrent import futures
import ast
import func.utility as util

def whatis(obj): return print(type(obj), "\n\t" + "\n\t".join(dir(obj)))


cfg = ConfigParser()
cfg.read('config.ini')


class MainWindow:

    def __init__(self):
        self.task_pool = futures.ThreadPoolExecutor(
            4)  # 多进程:ProcessPoolExecutor
        self.glade_file = "ui/UI.glade"
        self.builder = Gtk.Builder()
        self.builder.add_from_file(self.glade_file)
        self.builder.connect_signals(self)
        self.window = self.builder.get_object("main_window")
        self.edit_singe_scan = self.builder.get_object("Edit_Single_Scan")
        self.edit_singe_scan.drag_dest_unset()
        self.Gtk_Text_View = self.builder.get_object("gtk_text_view")
        self.Gtk_Text_View.drag_dest_unset()
        self.tree_view_target = self.builder.get_object("tree_view_target")
        self.tree_view_reports = self.builder.get_object("tree_view_reports")
        self.tree_view_vulnerabilities_info = self.builder.get_object(
            "tree_view_vulnerabilities_info")
        self.tree_view_sql_injection = self.builder.get_object(
            "tree_view_sql_injection")
        self.label_drop_file = self.builder.get_object("label_drop_file")
        enforce_target = Gtk.TargetEntry.new(
            'text/plain', Gtk.TargetFlags(4), 129)
        self.label_drop_file.drag_dest_set(
            Gtk.DestDefaults.ALL, [enforce_target], Gdk.DragAction.COPY)
        self.clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)

        # add column
        renderer = Gtk.CellRendererText()
        for i, column in enumerate(self.tree_view_target.get_columns()):
            column.pack_start(renderer, False)
            column.add_attribute(renderer, "text", i)
        for i, column in enumerate(self.tree_view_reports.get_columns()):
            column.pack_start(renderer, False)
            column.add_attribute(renderer, "text", i)
        for i, column in enumerate(self.tree_view_vulnerabilities_info.get_columns()):
            column.pack_start(renderer, True)
            column.add_attribute(renderer, "text", i)
        for i, column in enumerate(self.tree_view_sql_injection.get_columns()):
            column.pack_start(renderer, True)
            column.add_attribute(renderer, "text", i)

        self.list_store_target = self.builder.get_object("list_store_target")
        self.list_store_reports = self.builder.get_object("list_store_reports")
        self.list_store_vulnerabilities_info = self.builder.get_object(
            "list_store_vulnerabilities_info")
        self.list_store_sql_injection = self.builder.get_object(
            "list_store_sql_injection")

        self.ComboBox_Text_Host = self.builder.get_object("ComboBox_Text_Host")
        for scanner in cfg.sections():
            self.ComboBox_Text_Host.append_text(scanner)

        self.ComboBox_Text_Host.set_active(0)
        self.scan = ScanApi(cfg.get(self.ComboBox_Text_Host.get_active_text(), "host"),
                            cfg.get(self.ComboBox_Text_Host.get_active_text(), "key"))
        self.sql_api = SqlMapApi("127.0.0.1", "8775")
        self.vulnerabilities = VulnerabilitiesApi(
            self.scan.host, self.scan.headers)
        self.ComboBox_Text_Speed = self.builder.get_object(
            "ComboBox_Text_Speed")
        self.Edit_Description = self.builder.get_object("Edit_Description")
        self.Enable_Proxy = self.builder.get_object("Enable_Proxy")
        self.Proxy_Host = self.builder.get_object("Proxy_Host")
        self.Proxy_Port = self.builder.get_object("Proxy_Port")
        self.Scan_Menu = self.builder.get_object("Scan_Menu")
        self.Vulnerabilities_Menu = self.builder.get_object(
            "Vulnerabilities_Menu")
        self.Report_Menu = self.builder.get_object("Report_Menu")
        self.Sql_Injection_Menu = self.builder.get_object("Sql_Injection_Menu")
        self.File_Choose_Dialog = self.builder.get_object("File_Choose_Dialog")
        self.About = self.builder.get_object("About")
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
        self.task_pool.submit(self.scan.list_to_scan,
                              address.split(os.linesep), self)
        self.on_refresh_target_activate(widget)

    def on_button_batch_scan_clicked(self, widget, data=None):
        self.useless_func()
        print("批量扫描")
        text_buffer = self.Gtk_Text_View.get_buffer()
        text_targets_list = text_buffer.get_text(
            text_buffer.get_start_iter(), text_buffer.get_end_iter(), False)
        self.task_pool.submit(self.scan.list_to_scan,
                              text_targets_list.split(os.linesep), self)
        self.on_refresh_target_activate(widget)

    def on_button_clear_list_clicked(self, object, data=None):
        self.list_store_target.clear()

    def on_combobox_text_host_changed(self, combo, data=None):
        api_host, api_key = [cfg.get(combo.get_active_text(), "host"), cfg.get(
            combo.get_active_text(), "key")]
        self.scan = ScanApi(api_host, api_key)
        self.vulnerabilities = VulnerabilitiesApi(
            self.scan.host, self.scan.headers)

        return api_host, api_key

    def on_batch_del_clicked(self, widget, data=None):
        print("批量删除")
        model = self.tree_view_target.get_model()
        for row in model:
            print(row[1])
            self.scan.del_target(target_id=row[1])
        self.on_refresh_target_activate(widget)

    def on_tree_view_target_button_press_event(self, widget, event=None):
        if event.button == 3:  # right click
            self.Scan_Menu.popup(None, widget, None, None,
                                 event.button, event.time)

    def on_delete_target_activate(self, widget, event=None):
        selection = self.tree_view_target.get_selection()
        (model, path_list) = selection.get_selected_rows()
        for path in path_list:
            tree_iter = model.get_iter(path)
            value = model.get_value(tree_iter, 1)
            self.scan.del_target(value)
        self.on_refresh_target_activate(widget)

    def on_label_drop_file_drag_data_received(self, widget, context, x, y, sel, target_type, timestamp):
        file_path = urllib.parse.unquote(
            sel.get_text()).replace(os.linesep, "")
        print(file_path)
        text_buffer = self.Gtk_Text_View.get_buffer()
        with open(file=file_path[7:], mode="r") as f:
            text_buffer.set_text(f.read())
            self.Gtk_Text_View.set_buffer(text_buffer)

    def on_tree_view_reports_button_press_event(self, widget, event=None):
        if event.button == 3:  # right click
            self.Report_Menu.popup(
                None, widget, None, None, event.button, event.time)

    def on_refresh_report_activate(self, widget, event=None):
        print("刷新报告")
        self.scan.get_report_info(self.list_store_reports)

    def on_report_add_activate(self, widget, event=None):
        print("添加报告")
        model = self.tree_view_target.get_model()
        for row in model:
            print(row[1])
            self.scan.add_scan_to_report(scan_id=row[3])

    def on_delete_report_activate(self, widget, event=None):
        selection = self.tree_view_reports.get_selection()
        (model, path_list) = selection.get_selected_rows()
        for path in path_list:
            tree_iter = model.get_iter(path)
            value = model.get_value(tree_iter, 1)
            self.scan.del_report_from_scan(value)
        self.on_refresh_report_activate(widget)

    def on_clear_report_activate(self, widget, data=None):
        print("批量删除报告")
        model = self.tree_view_reports.get_model()
        for row in model:
            print(row[1])
            self.scan.del_report_from_scan(report_id=row[1])
        self.on_refresh_report_activate(widget)

    def on_dl_report_html_activate(self, widget, event=None):
        selection = self.tree_view_reports.get_selection()
        (model, path_list) = selection.get_selected_rows()
        for path in path_list:
            tree_iter = model.get_iter(path)
            value = model.get_value(tree_iter, 7)
            Gtk.show_uri_on_window(
                None, self.scan.host[:-8] + value, Gdk.CURRENT_TIME)

    def on_dl_report_pdf_activate(self, widget, event=None):
        selection = self.tree_view_reports.get_selection()
        (model, path_list) = selection.get_selected_rows()
        for path in path_list:
            tree_iter = model.get_iter(path)
            value = model.get_value(tree_iter, 7)[:-4] + "pdf"
            Gtk.show_uri_on_window(
                None, self.scan.host[:-8] + value, Gdk.CURRENT_TIME)

    def on_gtk_find_vulnerabilities_activate(self, widget, event=None):
        model = self.tree_view_target.get_model()
        for row in model:
            # self.vulnerabilities.get_vulnerabilities_by_scan_id(scan_id=row[3], scan_session=row[11],widget=self)
            self.task_pool.submit(self.vulnerabilities.get_vulnerabilities_by_scan_id, scan_id=row[3],
                                  scan_session=row[11], widget=self)
        # self.on_refresh_report_activate(widget)

    def on_high_vulnerabilities_clicked(self, widget, event=None):
        self.vulnerabilities.get_vulnerabilities_by_severity(
            severity=3, widget=self)

    def on_medium_vulnerabilities_clicked(self, widget, event=None):
        self.vulnerabilities.get_vulnerabilities_by_severity(
            severity=2, widget=self)

    def on_low_vulnerabilities_clicked(self, widget, event=None):
        self.vulnerabilities.get_vulnerabilities_by_severity(
            severity=1, widget=self)

    def on_info_vulnerabilities_clicked(self, widget, event=None):
        self.vulnerabilities.get_vulnerabilities_by_severity(
            severity=0, widget=self)

    def on_tree_view_vulnerabilities_info_button_press_event(self, widget, event=None):
        if event.button == 3:  # right click
            self.Vulnerabilities_Menu.popup(
                None, widget, None, None, event.button, event.time)

    def on_open_with_browser_activate(self, widget, event=None):
        selection = self.tree_view_vulnerabilities_info.get_selection()
        (model, path_list) = selection.get_selected_rows()
        for path in path_list:
            tree_iter = model.get_iter(path)
            target_url = model.get_value(tree_iter, 2)
            raw = model.get_value(tree_iter, 3)
            request_info = util.HTTPRequest(
                raw_http_request=ast.literal_eval(raw).decode())
            scheme, netloc, path, query, fragment = urllib.parse.urlsplit(
                target_url)
            value = scheme + "://" + netloc + request_info.path
            Gtk.show_uri_on_window(None, value, Gdk.CURRENT_TIME)

    def on_copy_requests_activate(self, widget, event=None):
        selection = self.tree_view_vulnerabilities_info.get_selection()
        (model, path_list) = selection.get_selected_rows()
        for path in path_list:
            tree_iter = model.get_iter(path)
            value = model.get_value(tree_iter, 3)
            self.clipboard.set_text(ast.literal_eval(value).decode(), -1)

    def on_send_to_sqlmap_activate(self, widget, event=None):
        selection = self.tree_view_vulnerabilities_info.get_selection()
        (model, path_list) = selection.get_selected_rows()
        for path in path_list:
            tree_iter = model.get_iter(path)
            raw = ast.literal_eval(model.get_value(tree_iter, 3)).decode()
            url = model.get_value(tree_iter, 2)
            point = model.get_value(tree_iter, 4)
            payload = ast.literal_eval(model.get_value(tree_iter, 5))
            original = model.get_value(tree_iter, 6)
            self.sql_api.add(target_url=url, raw=raw,
                             payloads=payload, point=point, original=original)

    def on_tree_view_sql_injection_button_press_event(self, widget, event=None):
        if event.button == 3:  # right click
            self.Sql_Injection_Menu.popup(
                None, widget, None, None, event.button, event.time)

    def on_refresh_task_activate(self, widget, event=None):
        self.sql_api.list(self)

    def on_del_empty_task_clicked(self, widget, event=None):
        model = self.tree_view_sql_injection.get_model()
        for row in model:
            if row[2] == "url":
                print(row[1])
                self.sql_api.del_task(task_id=row[1])
        self.on_refresh_task_activate(widget)

    def on_verify_sql_injection_clicked(self, widget, event=None):
        model = self.tree_view_vulnerabilities_info.get_model()
        for row in model:
            if row[0] == "sql_injection":
                print(row[1])
                raw = ast.literal_eval(row[3]).decode()
                url = row[2]
                point = row[4]
                payload = ast.literal_eval(row[5])
                original = row[6]
                self.sql_api.add(target_url=url, raw=raw,
                                 payloads=payload, point=point, original=original)
        self.on_refresh_task_activate(widget)

    def on_save_report_clicked(self, widget, event=None):
        self.File_Choose_Dialog.set_current_name("SQL注入报告.md")
        responder = self.File_Choose_Dialog.run()
        if responder == Gtk.ResponseType.OK:
            save_file_name = self.File_Choose_Dialog.get_filename()
            self.File_Choose_Dialog.hide()
            func.report.save_to_md(
                tree_view=self.tree_view_sql_injection, file_path=save_file_name)
        elif responder == Gtk.ResponseType.CANCEL:
            self.File_Choose_Dialog.hide()
        else:
            self.File_Choose_Dialog.hide()

    def on_gtk_about_activate(self, widget, event=None):
        responder = self.About.run()
        if responder == Gtk.ResponseType.DELETE_EVENT:
            self.About.hide()
        print(responder)

    def main(self):
        self.useless_func()
        Gtk.main()

    def useless_func(self):
        pass
