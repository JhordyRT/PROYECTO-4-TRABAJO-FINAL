import sys
import sqlite3
import tkinter as tk
from tkinter import filedialog, messagebox
from ipaddress import ip_network, ip_interface
import psutil
from threading import Timer
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException


class SubFormulario1(tk.Toplevel):
    def __init__(self, master=None):
        super().__init__(master)
        self.title("Calculadora IP")
        self.geometry("600x400")
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Dirección IP:").grid(row=0, column=0)
        self.ip_entry = tk.Entry(self)
        self.ip_entry.grid(row=0, column=1)

        self.opcion = tk.StringVar(value="host")
        tk.Radiobutton(self, text="Número de Hosts", variable=self.opcion, value="host").grid(row=1, column=0)
        self.entry_hosts = tk.Entry(self)
        self.entry_hosts.grid(row=1, column=1)

        tk.Radiobutton(self, text="Máscara de Subred", variable=self.opcion, value="subnet").grid(row=2, column=0)
        self.entry_subnets = tk.Entry(self)
        self.entry_subnets.grid(row=2, column=1)

        tk.Button(self, text="Calcular", command=self.calcular_subneteo).grid(row=3, column=0, columnspan=2)

        self.resultado_text = tk.Text(self, height=15, width=50)
        self.resultado_text.grid(row=4, column=0, columnspan=2)

    def calcular_subneteo(self):
        ip = self.ip_entry.get()
        if self.opcion.get() == "host":
            subnets = int(self.entry_hosts.get())
            network = ip_network(f"{ip}/{subnets}", strict=False)
        else:
            subnets = int(self.entry_subnets.get())
            network = ip_network(ip)

        network_address = network.network_address
        broadcast_address = network.broadcast_address
        first_usable = network.network_address + 1
        last_usable = network.broadcast_address - 1
        num_hosts = network.num_addresses
        wildcard_mask = ~int(network.netmask)

        self.resultado_text.delete(1.0, tk.END)
        self.resultado_text.insert(tk.END, f"Dirección IP: {ip}\n")
        self.resultado_text.insert(tk.END, f"Máscara de Subred: {network.netmask} (/ {network.prefixlen})\n")
        self.resultado_text.insert(tk.END, f"Dirección de Red: {network_address}\n")
        self.resultado_text.insert(tk.END, f"Dirección de Broadcast: {broadcast_address}\n")
        self.resultado_text.insert(tk.END, f"Primera Dirección IP Utilizable: {first_usable}\n")
        self.resultado_text.insert(tk.END, f"Última Dirección IP Utilizable: {last_usable}\n")
        self.resultado_text.insert(tk.END, f"Número de Hosts: {num_hosts} ({num_hosts - 2} utilizables)\n")
        self.resultado_text.insert(tk.END, f"Máscara Wildcard: {wildcard_mask}\n")
        self.resultado_text.insert(tk.END, f"Representación Binaria de la IP: {ip_interface(ip).ip.packed}\n")
        self.resultado_text.insert(tk.END, f"Representación Binaria de la Máscara de Subred: {ip_interface(ip).netmask.packed}\n")
        self.resultado_text.insert(tk.END, f"Clase de Red: {network_address.version}\n")


class SubFormulario2(tk.Toplevel):
    def __init__(self, master=None):
        super().__init__(master)
        self.title("Visor de Logs")
        self.geometry("600x400")
        self.create_widgets()

    def create_widgets(self):
        tk.Button(self, text="Cargar Archivo de Log", command=self.cargar_archivo_log).grid(row=0, column=0, columnspan=3)
        tk.Label(self, text="Fecha:").grid(row=1, column=0)
        self.entry_fecha = tk.Entry(self)
        self.entry_fecha.grid(row=1, column=1)

        tk.Label(self, text="Severidad:").grid(row=2, column=0)
        self.entry_severidad = tk.Entry(self)
        self.entry_severidad.grid(row=2, column=1)

        tk.Label(self, text="Origen:").grid(row=3, column=0)
        self.entry_origen = tk.Entry(self)
        self.entry_origen.grid(row=3, column=1)

        tk.Button(self, text="Filtrar Logs", command=self.filtrar_logs).grid(row=4, column=0, columnspan=3)
        tk.Button(self, text="Mostrar Estadísticas", command=self.mostrar_estadisticas).grid(row=5, column=0, columnspan=3)

        self.resultado_text = tk.Text(self, height=15, width=50)
        self.resultado_text.grid(row=6, column=0, columnspan=3)

    def cargar_archivo_log(self):
        archivo = filedialog.askopenfilename()
        with open(archivo, 'r') as f:
            logs = f.readlines()

        conn = sqlite3.connect('network_tools.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS logs (fecha TEXT, severidad TEXT, origen TEXT, mensaje TEXT)''')
        for log in logs:
            fecha, severidad, origen, mensaje = log.split(' ', 3)
            c.execute('''INSERT INTO logs VALUES (?, ?, ?, ?)''', (fecha, severidad, origen, mensaje))
        conn.commit()
        conn.close()

    def filtrar_logs(self):
        fecha = self.entry_fecha.get()
        severidad = self.entry_severidad.get()
        origen = self.entry_origen.get()

        conn = sqlite3.connect('network_tools.db')
        c = conn.cursor()
        query = "SELECT * FROM logs WHERE 1=1"
        params = []
        if fecha:
            query += " AND fecha = ?"
            params.append(fecha)
        if severidad:
            query += " AND severidad = ?"
            params.append(severidad)
        if origen:
            query += " AND origen = ?"
            params.append(origen)
        c.execute(query, params)
        logs = c.fetchall()
        conn.close()

        self.resultado_text.delete(1.0, tk.END)
        for log in logs:
            self.resultado_text.insert(tk.END, f"{log}\n")

    def mostrar_estadisticas(self):
        conn = sqlite3.connect('network_tools.db')
        c = conn.cursor()

        c.execute("SELECT severidad, COUNT(*) FROM logs GROUP BY severidad")
        logs_por_severidad = c.fetchall()

        c.execute("SELECT origen, COUNT(*) FROM logs GROUP BY origen")
        logs_por_origen = c.fetchall()

        conn.close()

        self.resultado_text.delete(1.0, tk.END)
        self.resultado_text.insert(tk.END, "Logs por Severidad:\n")
        for log in logs_por_severidad:
            self.resultado_text.insert(tk.END, f"{log[0]}: {log[1]}\n")

        self.resultado_text.insert(tk.END, "\nLogs por Origen:\n")
        for log in logs_por_origen:
            self.resultado_text.insert(tk.END, f"{log[0]}: {log[1]}\n")


class SubFormulario3(tk.Toplevel):
    def __init__(self, master=None):
        super().__init__(master)
        self.title("Análisis de PC")
        self.geometry("600x400")
        self.create_widgets()
        self.crear_tabla()

    def create_widgets(self):
        tk.Button(self, text="Capturar Datos", command=self.capturar_datos).grid(row=0, column=0)
        tk.Button(self, text="Captura en Tiempo Real", command=self.capturar_en_tiempo_real).grid(row=0, column=1)
        tk.Button(self, text="Detener Captura", command=self.detener_captura).grid(row=0, column=2)
        tk.Button(self, text="Analizar Datos", command=self.analizar_datos).grid(row=0, column=3)

        self.resultado_text = tk.Text(self, height=15, width=100)
        self.resultado_text.grid(row=1, column=0, columnspan=4)

    def crear_tabla(self):
        conn = sqlite3.connect('network_tools.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS pc_analysis (disco TEXT, memoria TEXT, cpu TEXT, temperatura TEXT)''')
        conn.commit()
        conn.close()

    def guardar_datos_en_db(self, disco, memoria, cpu, temperatura):
        conn = sqlite3.connect('network_tools.db')
        c = conn.cursor()
        c.execute('''INSERT INTO pc_analysis VALUES (?, ?, ?, ?)''', (disco, memoria, cpu, temperatura))
        conn.commit()
        conn.close()

    def capturar_datos(self):
        discos = psutil.disk_usage('/')
        memoria = psutil.virtual_memory()
        cpu = psutil.cpu_percent(interval=1)
        temperatura = "N/A"  # Algunos sistemas pueden no proporcionar datos de temperatura

        try:
            temp = psutil.sensors_temperatures()
            if 'coretemp' in temp:
                temperatura = temp['coretemp'][0].current
        except AttributeError:
            pass

        datos = (
            f"Total: {discos.total}, Usado: {discos.used}, Libre: {discos.free}, Porcentaje: {discos.percent}",
            f"Total: {memoria.total}, Disponible: {memoria.available}, Usado: {memoria.used}, Porcentaje: {memoria.percent}",
            f"Porcentaje de Uso de CPU: {cpu}",
            f"Temperatura: {temperatura} °C"
        )
        self.guardar_datos_en_db(*datos)
        self.mostrar_resultado(datos)

    def mostrar_resultado(self, datos):
        self.resultado_text.delete(1.0, tk.END)
        labels = ["Disco Duro: ", "Memoria: ", "CPU: ", "Temperatura: "]
        for label, dato in zip(labels, datos):
            self.resultado_text.insert(tk.END, f"{label}{dato}\n")

    def capturar_en_tiempo_real(self):
        self.capturar_datos()
        self.timer = Timer(10, self.capturar_en_tiempo_real)  # Captura cada 10 segundos
        self.timer.start()

    def detener_captura(self):
        self.timer.cancel()

    def analizar_datos(self):
        conn = sqlite3.connect('network_tools.db')
        c = conn.cursor()
        c.execute("SELECT * FROM pc_analysis")
        datos = c.fetchall()
        conn.close()

        self.resultado_text.delete(1.0, tk.END)
        for dato in datos:
            self.resultado_text.insert(tk.END, f"{dato}\n")


class SubFormulario4(tk.Toplevel):
    def __init__(self, master=None):
        super().__init__(master)
        self.title("Netmiko - Conexión de Red")
        self.geometry("600x400")
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Host:").grid(row=0, column=0)
        self.entry_host = tk.Entry(self)
        self.entry_host.grid(row=0, column=1)

        tk.Label(self, text="Username:").grid(row=1, column=0)
        self.entry_username = tk.Entry(self)
        self.entry_username.grid(row=1, column=1)

        tk.Label(self, text="Password:").grid(row=2, column=0)
        self.entry_password = tk.Entry(self, show="*")
        self.entry_password.grid(row=2, column=1)

        tk.Label(self, text="Device Type:").grid(row=3, column=0)
        self.entry_device_type = tk.Entry(self)
        self.entry_device_type.grid(row=3, column=1)

        tk.Label(self, text="Comando Personalizado:").grid(row=4, column=0)
        self.entry_comando = tk.Entry(self)
        self.entry_comando.grid(row=4, column=1)

        tk.Button(self, text="Ejecutar Comando show version", command=self.ejecutar_comando_basico).grid(row=5, column=0, columnspan=2)
        tk.Button(self, text="Obtener Estado de Interfaces", command=self.obtener_estado_interfaces).grid(row=6, column=0, columnspan=2)
        tk.Button(self, text="Ejecutar Comando Personalizado", command=self.ejecutar_comando_personalizado).grid(row=7, column=0, columnspan=2)

        self.resultado_text = tk.Text(self, height=15, width=50)
        self.resultado_text.grid(row=8, column=0, columnspan=2)

    def conectar_dispositivo(self, host, username, password, device_type):
        dispositivo = {
            'device_type': device_type,
            'host': host,
            'username': username,
            'password': password,
        }
        try:
            conexion = ConnectHandler(**dispositivo)
            return conexion
        except NetmikoTimeoutException:
            messagebox.showerror("Error", "Tiempo de espera agotado al intentar conectar al dispositivo.")
        except NetmikoAuthenticationException:
            messagebox.showerror("Error", "Error de autenticación, verifica las credenciales.")
        except Exception as e:
            messagebox.showerror("Error", f"Error inesperado: {e}")

    def ejecutar_comando_basico(self):
        host = self.entry_host.get()
        username = self.entry_username.get()
        password = self.entry_password.get()
        device_type = self.entry_device_type.get()

        conexion = self.conectar_dispositivo(host, username, password, device_type)
        if conexion:
            try:
                salida = conexion.send_command("show version")
                self.resultado_text.delete(1.0, tk.END)
                self.resultado_text.insert(tk.END, salida)
            except Exception as e:
                messagebox.showerror("Error", f"Error al ejecutar comando: {e}")
            finally:
                conexion.disconnect()

    def obtener_estado_interfaces(self):
        host = self.entry_host.get()
        username = self.entry_username.get()
        password = self.entry_password.get()
        device_type = self.entry_device_type.get()

        conexion = self.conectar_dispositivo(host, username, password, device_type)
        if conexion:
            try:
                salida = conexion.send_command("show ip interface brief")
                self.resultado_text.delete(1.0, tk.END)
                self.resultado_text.insert(tk.END, salida)
            except Exception as e:
                messagebox.showerror("Error", f"Error al obtener el estado de las interfaces: {e}")
            finally:
                conexion.disconnect()

    def ejecutar_comando_personalizado(self):
        host = self.entry_host.get()
        username = self.entry_username.get()
        password = self.entry_password.get()
        device_type = self.entry_device_type.get()
        comando = self.entry_comando.get()

        conexion = self.conectar_dispositivo(host, username, password, device_type)
        if conexion:
            try:
                salida = conexion.send_command(comando)
                self.resultado_text.delete(1.0, tk.END)
                self.resultado_text.insert(tk.END, salida)
            except Exception as e:
                messagebox.showerror("Error", f"Error al ejecutar comando: {e}")
            finally:
                conexion.disconnect()


class FormularioPrincipal(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Formulario Principal")
        self.geometry("300x200")
        self.create_widgets()

    def create_widgets(self):
        tk.Button(self, text="Calculadora IP", command=self.abrir_subformulario1).pack(pady=10)
        tk.Button(self, text="Visor de Logs", command=self.abrir_subformulario2).pack(pady=10)
        tk.Button(self, text="Análisis de PC", command=self.abrir_subformulario3).pack(pady=10)
        tk.Button(self, text="Netmiko - Conexión de Red", command=self.abrir_subformulario4).pack(pady=10)

    def abrir_subformulario1(self):
        subformulario = SubFormulario1(self)
        subformulario.grab_set()

    def abrir_subformulario2(self):
        subformulario = SubFormulario2(self)
        subformulario.grab_set()

    def abrir_subformulario3(self):
        subformulario = SubFormulario3(self)
        subformulario.grab_set()

    def abrir_subformulario4(self):
        subformulario = SubFormulario4(self)
        subformulario.grab_set()


if __name__ == "__main__":
    app = FormularioPrincipal()
    app.mainloop()
