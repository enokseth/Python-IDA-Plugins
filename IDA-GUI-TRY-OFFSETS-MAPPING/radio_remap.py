#!/bin/python3
import idaapi, idautils, idc
from idaapi import PluginForm

try:
    from PyQt5 import QtWidgets, QtCore
except ImportError:
    from PySide2 import QtWidgets, QtCore

import csv
import os

class RadioMapperForm(PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.mapping = {}

        self.table = QtWidgets.QTableWidget(self.parent)
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Address", "Mapped Byte", "Character"])
        self.table.cellDoubleClicked.connect(self.jump_to_address)
        self.table.setSortingEnabled(True)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.table)

        self.import_button = QtWidgets.QPushButton("Importer Mapping CSV")
        self.import_button.clicked.connect(self.import_csv)
        layout.addWidget(self.import_button)

        self.scan_button = QtWidgets.QPushButton("Scanner les Zones")
        self.scan_button.clicked.connect(self.scan_memory)
        layout.addWidget(self.scan_button)

        self.parent.setLayout(layout)

    def import_csv(self):
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self.parent, "Importer CSV", os.path.expanduser("~"), "CSV Files (*.csv)")
        if not file_path:
            return

        self.mapping.clear()
        with open(file_path, "r") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                try:
                    addr = int(row["Address"], 16)
                    byte = int(row["Hex Value"], 16)
                    self.mapping[addr] = byte
                except Exception as e:
                    print(f"[!] Erreur ligne CSV: {e}")
        print(f"[✓] Mapping importé depuis {file_path} ({len(self.mapping)} entrées)")

    def scan_memory(self):
        self.table.setRowCount(0)
        if not self.mapping:
            print("[!] Aucun mapping importé.")
            return

        for ea in idautils.Heads():
            if idc.is_data(idc.get_full_flags(ea)):
                byte = idc.get_wide_byte(ea)
                mapped = self.mapping.get(ea)
                if mapped is not None and mapped == byte:
                    char = chr(byte) if 0x20 <= byte <= 0x7E else f"<0x{byte:02X}>"
                    row = self.table.rowCount()
                    self.table.insertRow(row)
                    self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(f"0x{ea:X}"))
                    self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(f"0x{byte:02X}"))
                    self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(char))
                    idc.set_cmt(ea, f"Mapped char: {char}", 0)

        self.table.resizeColumnsToContents()
        print(f"[+] Scan terminé. {self.table.rowCount()} correspondances trouvées.")

    def jump_to_address(self, row, column):
        addr_item = self.table.item(row, 0)
        if addr_item:
            addr_str = addr_item.text()
            try:
                ea = int(addr_str, 16)
                idaapi.jumpto(ea)
            except ValueError:
                pass

    def OnClose(self, form):
        return

class RadioMapperPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Radio IMG Char Mapper"
    help = "Import a mapping table and scan memory for matches"
    wanted_name = "Radio Mapper"
    wanted_hotkey = "Ctrl-Shift-R"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        if hasattr(self, 'form') and self.form:
            try:
                self.form.OnClose(None)
            except Exception:
                pass
            self.form = None

        print(f"[i] Chargement de {idaapi.get_input_file_path()}")
        self.form = RadioMapperForm()
        self.form.Show("Radio IMG Mapper")

    def term(self):
        return

def PLUGIN_ENTRY():
    return RadioMapperPlugin()
