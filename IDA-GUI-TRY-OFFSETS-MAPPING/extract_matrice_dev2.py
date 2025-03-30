#!/bin/python3
import idaapi, idautils, idc
from idaapi import PluginForm

# Qt import (PyQt5 or PySide2 depending on your setup)
try:
    from PyQt5 import QtWidgets, QtCore
except ImportError:
    from PySide2 import QtWidgets, QtCore

import csv
import os

class MappingResultsForm(PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)

        self.table = QtWidgets.QTableWidget(self.parent)
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Address", "Hex Value", "Character"])
        self.table.cellDoubleClicked.connect(self.jump_to_address)
        self.table.setSortingEnabled(True)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.table)

        self.export_button = QtWidgets.QPushButton("Exporter CSV")
        self.export_button.clicked.connect(self.export_csv)
        layout.addWidget(self.export_button)

        self.parent.setLayout(layout)

        self.buffer_start, self.buffer_data = self.find_mapping_buffer()
        self.populate_table()

    def find_mapping_buffer(self):
        """Scan des segments pour trouver une table de bytes non imprimables / table suspecte."""
        for seg_ea in idautils.Segments():
            seg_end = idc.get_segm_end(seg_ea)
            seg_data = idc.get_bytes(seg_ea, seg_end - seg_ea)
            if not seg_data:
                continue
            data = bytearray(seg_data)
            if len(data) >= 0x40:
                # Heuristique simple : contient au moins 50% de non imprimables + char visibles mixtes
                printable = sum(1 for b in data if 0x20 <= b <= 0x7E)
                non_print = len(data) - printable
                if non_print > printable and printable > 10:
                    return seg_ea, data
        return None, b""

    def populate_table(self):
        if not self.buffer_data:
            print("[!] Aucun buffer suspect trouvé.")
            return

        for offset, byte in enumerate(self.buffer_data):
            addr = self.buffer_start + offset
            if not idc.is_loaded(addr):
                continue
            char = chr(byte) if 0x20 <= byte <= 0x7E else "<0x%02X>" % byte

            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QtWidgets.QTableWidgetItem("0x%X" % addr))
            self.table.setItem(row, 1, QtWidgets.QTableWidgetItem("0x%02X" % byte))
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(char))

        self.table.resizeColumnsToContents()
        print(f"[+] Mapping table trouvée @ 0x{self.buffer_start:X} - {len(self.buffer_data)} octets")

    def jump_to_address(self, row, column):
        addr_item = self.table.item(row, 0)
        if addr_item:
            addr_str = addr_item.text()
            try:
                ea = int(addr_str, 16)
                idaapi.jumpto(ea)
            except ValueError:
                pass

    def export_csv(self):
        default_path = os.path.expanduser("~/char_mapping_export.csv")
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Exporter CSV", default_path, "CSV Files (*.csv)")
        if not file_path:
            return

        with open(file_path, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Address", "Hex Value", "Character"])
            for row in range(self.table.rowCount()):
                addr = self.table.item(row, 0).text()
                hex_val = self.table.item(row, 1).text()
                char = self.table.item(row, 2).text()
                writer.writerow([addr, hex_val, char])
        print(f"[✓] Export CSV: {file_path}")

    def OnClose(self, form):
        return

class MappingPluginOne(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Mapping Table Extractor - Char Arm 1"
    help = "Scan and extract special char table"
    wanted_name = "Char Mapping Viewer"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        if hasattr(self, 'form') and self.form:
            try:
                self.form.OnClose(None)
            except Exception:
                pass
            self.form = None  # Libère la référence

        print(f"[i] Analyse de : {idaapi.get_input_file_path()}")
        self.form = MappingResultsForm()
        self.form.Show("Char Arm 1 Mapping Analysis")

    def term(self):
        return

def PLUGIN_ENTRY():
    return MappingPluginOne()
