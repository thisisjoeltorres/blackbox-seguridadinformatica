"""
Caja Fuerte - Seguridad Informática (proyecto final del corte)

Convierte una carpeta en una "caja fuerte": al BLOQUEARLA cifra todos los
archivos (y también sus nombres) con AES-256-GCM usando una contraseña.
Al DESBLOQUEARLA con la contraseña correcta, todo vuelve a su lugar y se puede
copiar, pegar, cortar y modificar normal desde el Explorador o el Finder.

Funciona en Windows y Mac (también Linux).

Instalación (una sola vez):
    pip install cryptography customtkinter

Ejecutar:
    python caja_fuerte.py
"""

import base64
import json
import os
import queue
import secrets
import subprocess
import sys
import threading
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# Constantes
NOMBRE_META = "caja_fuerte.meta"   # archivo de control: si existe, la carpeta está BLOQUEADA
EXTENSION = ".enc"                 # los archivos cifrados quedan con nombres al azar + .enc
CHUNK = 1024 * 1024                # los archivos se cifran de a 1 MB (así no se llena la RAM)
MAGIC = b"CFV1"                    # marca que va al inicio de cada archivo cifrado
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1   # qué tan "lenta" es la derivación de la clave
MIN_PASSWORD = 8                   # largo mínimo de la contraseña


class ErrorCaja(Exception):
    """Error propio del programa, con un mensaje listo para mostrarle al usuario."""


# Clave de cifrado a partir de la contraseña definida por el usuario.
def derivar_clave(password, salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
    """Convierte la contraseña en una clave de 32 bytes (256 bits) para AES.

    Nunca se usa la contraseña directa como clave. Se pasa por scrypt junto con
    un 'salt' aleatorio. Scrypt es lento y gasta memoria a propósito, así
    adivinar contraseñas por fuerza bruta se vuelve carísimo.
    """
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return kdf.derive(password.encode("utf-8"))


# Metodos para cifrar o decifrar un archivo. Para nuestro caso especifico usamos: AES-GCM por pedazos
def cifrar_archivo(origen, destino, clave, id_archivo):
    """Cifra un archivo en pedazos de 1 MB con AES-GCM.

    Cada pedazo usa un 'nonce' distinto (prefijo al azar + contador). GCM además
    mete una etiqueta de autenticación: si alguien cambia aunque sea un byte del
    archivo cifrado, al descifrar se detecta. Al último pedazo se le marca como
    "último" para que nadie pueda cortar el archivo sin que se note.
    """
    aes = AESGCM(clave)
    prefijo = secrets.token_bytes(8)
    contador = 0

    with open(origen, "rb") as f, open(destino, "wb") as salida:
        salida.write(MAGIC + prefijo)
        actual = f.read(CHUNK)
        while True:
            # Si el pedazo está completo, miro si todavía hay más archivo.
            siguiente = f.read(CHUNK) if len(actual) == CHUNK else b""
            es_ultimo = len(siguiente) == 0

            nonce = prefijo + contador.to_bytes(4, "big")
            extra = id_archivo.encode() + (b"1" if es_ultimo else b"0")
            salida.write(aes.encrypt(nonce, actual, extra))

            if es_ultimo:
                break
            actual = siguiente
            contador += 1


def descifrar_archivo(origen, destino, clave, id_archivo):
    """Hace el camino inverso de cifrar_archivo()."""
    aes = AESGCM(clave)
    tam_bloque = CHUNK + 16   # cada pedazo cifrado trae 16 bytes extra (la etiqueta)

    with open(origen, "rb") as f, open(destino, "wb") as salida:
        cabecera = f.read(12)
        if cabecera[:4] != MAGIC:
            raise ErrorCaja("Un archivo de la caja está dañado o no es válido.")
        prefijo = cabecera[4:12]
        contador = 0

        actual = f.read(tam_bloque)
        while True:
            siguiente = f.read(tam_bloque) if len(actual) == tam_bloque else b""
            es_ultimo = len(siguiente) == 0

            nonce = prefijo + contador.to_bytes(4, "big")
            extra = id_archivo.encode() + (b"1" if es_ultimo else b"0")
            try:
                salida.write(aes.decrypt(nonce, actual, extra))
            except (InvalidTag, ValueError):
                raise ErrorCaja("Un archivo fue modificado o está corrupto.")

            if es_ultimo:
                break
            actual = siguiente
            contador += 1


# Metodos para comprobar la carpeta.
def es_caja_cerrada(carpeta):
    """Una carpeta está bloqueada si tiene el archivo de control."""
    return (Path(carpeta) / NOMBRE_META).is_file()


def validar_carpeta(carpeta):
    """Evita errores graves, como bloquear toda tu carpeta personal o un disco."""
    carpeta = Path(carpeta)
    if not carpeta.is_dir():
        raise ErrorCaja("La carpeta elegida no existe.")
    if carpeta.parent == carpeta or carpeta.resolve() == Path.home().resolve():
        raise ErrorCaja("Por seguridad no se puede usar un disco completo ni tu carpeta personal.")


def borrar_si_existe(ruta):
    try:
        Path(ruta).unlink()
    except FileNotFoundError:
        pass


def ruta_segura(carpeta, ruta_relativa):
    """Arma la ruta final de un archivo y confirma que quede DENTRO de la carpeta."""
    partes = ruta_relativa.split("/")
    if any(p in ("", ".", "..") for p in partes):
        raise ErrorCaja("La caja tiene una ruta inválida.")
    destino = carpeta.joinpath(*partes)
    if carpeta.resolve() not in destino.resolve().parents:
        raise ErrorCaja("La caja tiene una ruta inválida.")
    return destino


def nombre_libre(ruta):
    """Si ya existe un archivo con ese nombre, le agrega (restaurado) para no pisarlo."""
    if not ruta.exists():
        return ruta
    n = 1
    while True:
        candidata = ruta.with_name(f"{ruta.stem} (restaurado {n}){ruta.suffix}")
        if not candidata.exists():
            return candidata
        n += 1


# Bloquear carpeta
def bloquear(carpeta, password, progreso=None):
    """Cifra todo el contenido de la carpeta y lo deja ilegible.

    Orden de pasos (pensado para que NUNCA se pierdan datos):
      1. Cifrar cada archivo a una copia .enc con nombre al azar.
      2. Guardar el archivo de control (con la lista cifrada de nombres originales).
      3. Solo si todo salió bien, borrar los originales.
    Si algo falla en los pasos 1 o 2, se borran las copias y los originales quedan intactos.
    """
    carpeta = Path(carpeta)
    validar_carpeta(carpeta)
    if es_caja_cerrada(carpeta):
        raise ErrorCaja("Esta carpeta ya está bloqueada.")

    #   Listar archivos y subcarpetas (los accesos directos/symlinks se ignoran)  
    archivos, subcarpetas = [], []
    for raiz, dirs, nombres in os.walk(carpeta):
        raiz = Path(raiz)
        for d in dirs:
            if not (raiz / d).is_symlink():
                subcarpetas.append(raiz / d)
        for n in nombres:
            if not (raiz / n).is_symlink():
                archivos.append(raiz / n)

    if not archivos:
        raise ErrorCaja("La carpeta no tiene archivos para proteger.")

    #   Clave nueva para esta vez (salt al azar)  
    salt = secrets.token_bytes(16)
    clave = derivar_clave(password, salt)

    manifiesto = {
        "dirs": [d.relative_to(carpeta).as_posix() for d in subcarpetas],
        "files": [],
    }
    creados = []

    try:
        # Paso 1: cifrar cada archivo
        for i, ruta in enumerate(archivos, start=1):
            id_archivo = secrets.token_hex(8)            # nombre al azar: no revela nada
            destino = carpeta / (id_archivo + EXTENSION)
            creados.append(destino)
            cifrar_archivo(ruta, destino, clave, id_archivo)
            manifiesto["files"].append({"id": id_archivo, "path": ruta.relative_to(carpeta).as_posix()})
            if progreso:
                progreso(i, len(archivos), ruta.name)

        # Paso 2: guardar el archivo de control. La lista de nombres originales va CIFRADA.
        nonce = secrets.token_bytes(12)
        lista_cifrada = AESGCM(clave).encrypt(nonce, json.dumps(manifiesto).encode("utf-8"), b"manifiesto")
        meta = {
            "version": 1,
            "kdf": {"nombre": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "manifiesto": base64.b64encode(lista_cifrada).decode(),
        }
        ruta_meta = carpeta / NOMBRE_META
        creados.append(ruta_meta)
        ruta_meta.write_text(json.dumps(meta), encoding="utf-8")

    except Exception:
        # Algo falló: limpio lo que alcancé a crear y los originales siguen intactos.
        for c in creados:
            borrar_si_existe(c)
        raise

    # Paso 3: ya está todo cifrado y guardado, ahora sí borro los originales.
    for ruta in archivos:
        borrar_si_existe(ruta)
    for d in sorted(subcarpetas, key=lambda x: len(x.parts), reverse=True):
        try:
            d.rmdir()   # solo borra si quedó vacía
        except OSError:
            pass


# Desbloquear carpeta
def desbloquear(carpeta, password, progreso=None):
    """Verifica la contraseña, descifra todo y deja la carpeta como estaba."""
    carpeta = Path(carpeta)
    validar_carpeta(carpeta)
    ruta_meta = carpeta / NOMBRE_META
    if not ruta_meta.is_file():
        raise ErrorCaja("Esta carpeta no está bloqueada.")

    try:
        meta = json.loads(ruta_meta.read_text(encoding="utf-8"))
        salt = base64.b64decode(meta["salt"])
        nonce = base64.b64decode(meta["nonce"])
        lista_cifrada = base64.b64decode(meta["manifiesto"])
        k = meta["kdf"]
    except Exception:
        raise ErrorCaja("El archivo de control de la caja está dañado.")

    # Derivo la clave y pruebo abrir la lista de archivos. Si la contraseña
    # está mal, GCM falla aquí mismo y no se toca nada.
    clave = derivar_clave(password, salt, k["n"], k["r"], k["p"])
    try:
        datos = AESGCM(clave).decrypt(nonce, lista_cifrada, b"manifiesto")
    except InvalidTag:
        raise ErrorCaja("Contraseña incorrecta.")
    manifiesto = json.loads(datos.decode("utf-8"))

    # Confirmo que estén todos los archivos cifrados antes de empezar
    for item in manifiesto["files"]:
        if not (carpeta / (item["id"] + EXTENSION)).is_file():
            raise ErrorCaja("Faltan archivos dentro de la caja (alguien los borró o movió).")

    # Recreo las subcarpetas
    for d in manifiesto["dirs"]:
        ruta_segura(carpeta, d).mkdir(parents=True, exist_ok=True)

    # Descifro cada archivo a su lugar original
    restaurados = []
    try:
        total = len(manifiesto["files"])
        for i, item in enumerate(manifiesto["files"], start=1):
            destino = nombre_libre(ruta_segura(carpeta, item["path"]))
            destino.parent.mkdir(parents=True, exist_ok=True)
            restaurados.append(destino)
            descifrar_archivo(carpeta / (item["id"] + EXTENSION), destino, clave, item["id"])
            if progreso:
                progreso(i, total, destino.name)
    except Exception:
        for r in restaurados:      # si algo falla, vuelvo a dejarla bloqueada y limpia
            borrar_si_existe(r)
        raise

    # Todo salió bien: ya no se necesitan los archivos cifrados ni el de control.
    for item in manifiesto["files"]:
        borrar_si_existe(carpeta / (item["id"] + EXTENSION))
    borrar_si_existe(ruta_meta)


# Simplemente un boton para abrir la carpeta seleccionada en ese instante con Explorer/Finder.
def abrir_en_explorador(ruta):
    if sys.platform.startswith("win"):
        os.startfile(ruta)
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(ruta)])
    else:
        subprocess.Popen(["xdg-open", str(ruta)])


# Aqui esta la interfaz grafica, para este caso particular, se usa CustomTkinter.
try:
    import customtkinter as ctk
    from tkinter import filedialog, messagebox
except ImportError:
    print("Falta instalar la interfaz. Corre:  pip install cryptography customtkinter")
    sys.exit(1)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

COLOR_BLOQUEAR = ("#c0392b", "#a93226")     # rojo (color normal, color al pasar el mouse)
COLOR_DESBLOQUEAR = ("#2e8b57", "#256f46")  # verde


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Caja Fuerte")
        self.geometry("520x680")
        self.resizable(False, False)

        self.carpeta = None            # carpeta que eligió el usuario
        self.ocupado = False           # True mientras se cifra/descifra
        self.cola = queue.Queue()      # el hilo de trabajo le avisa a la ventana por aquí

        # Si intentan cerrar en medio de una operación, no los dejamos.
        self.protocol("WM_DELETE_WINDOW", self.al_cerrar)

        #    Título   
        ctk.CTkLabel(self, text="🔐 Caja Fuerte", font=ctk.CTkFont(size=30, weight="bold")).pack(pady=(24, 0))
        ctk.CTkLabel(self, text="Protege cualquier carpeta con una contraseña",
                     text_color="gray70").pack(pady=(0, 16))

        #    Tarjeta principal   
        tarjeta = ctk.CTkFrame(self, corner_radius=16)
        tarjeta.pack(fill="x", padx=24)

        ctk.CTkLabel(tarjeta, text="Carpeta", anchor="w").pack(fill="x", padx=18, pady=(16, 2))
        fila = ctk.CTkFrame(tarjeta, fg_color="transparent")
        fila.pack(fill="x", padx=18)
        self.var_ruta = ctk.StringVar(value="Ninguna carpeta elegida")
        ctk.CTkEntry(fila, textvariable=self.var_ruta, state="readonly").pack(side="left", fill="x", expand=True)
        ctk.CTkButton(fila, text="Elegir", width=80, command=self.elegir_carpeta).pack(side="left", padx=(8, 0))

        # Etiqueta que dice si la carpeta está bloqueada o abierta
        self.lbl_estado = ctk.CTkLabel(tarjeta, text="Elige una carpeta para empezar",
                                       font=ctk.CTkFont(size=15, weight="bold"), text_color="gray70")
        self.lbl_estado.pack(pady=14)

        ctk.CTkLabel(tarjeta, text="Contraseña", anchor="w").pack(fill="x", padx=18)
        self.ent_pass = ctk.CTkEntry(tarjeta, show="•")
        self.ent_pass.pack(fill="x", padx=18, pady=(2, 8))

        # La confirmación solo aparece cuando se va a BLOQUEAR
        self.marco_confirmar = ctk.CTkFrame(tarjeta, fg_color="transparent")
        ctk.CTkLabel(self.marco_confirmar, text="Confirmar contraseña", anchor="w").pack(fill="x")
        self.ent_confirmar = ctk.CTkEntry(self.marco_confirmar, show="•")
        self.ent_confirmar.pack(fill="x", pady=(2, 8))

        self.var_mostrar = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(tarjeta, text="Mostrar contraseña", variable=self.var_mostrar,
                        command=self.alternar_mostrar).pack(anchor="w", padx=18, pady=(0, 16))

        # Botón principal
        self.btn_accion = ctk.CTkButton(self, text="Elige una carpeta", height=46, state="disabled",
                                        font=ctk.CTkFont(size=16, weight="bold"), command=self.accion)
        self.btn_accion.pack(fill="x", padx=24, pady=(18, 8))

        self.btn_abrir = ctk.CTkButton(self, text="Abrir carpeta", height=34, state="disabled",
                                       fg_color="transparent", border_width=2, command=self.abrir_carpeta)
        self.btn_abrir.pack(fill="x", padx=24)

        # Progreso
        self.barra = ctk.CTkProgressBar(self)
        self.barra.set(0)
        self.barra.pack(fill="x", padx=24, pady=(20, 4))
        self.lbl_progreso = ctk.CTkLabel(self, text="", text_color="gray70")
        self.lbl_progreso.pack()

        ctk.CTkLabel(self, text="⚠ Si olvidas la contraseña, los archivos NO se pueden recuperar.",
                     text_color="#e0a030", font=ctk.CTkFont(size=12)).pack(side="bottom", pady=14)

    # Pequeñas funciones de ayuda de la ventana   
    def alternar_mostrar(self):
        """Muestra u oculta la contraseña."""
        caracter = "" if self.var_mostrar.get() else "•"
        self.ent_pass.configure(show=caracter)
        self.ent_confirmar.configure(show=caracter)

    def elegir_carpeta(self):
        if self.ocupado:
            return
        ruta = filedialog.askdirectory(title="Elige la carpeta")
        if ruta:
            self.carpeta = Path(ruta)
            self.var_ruta.set(str(self.carpeta))
            self.limpiar_campos()
            self.actualizar_estado()

    def limpiar_campos(self):
        self.ent_pass.delete(0, "end")
        self.ent_confirmar.delete(0, "end")
        self.barra.set(0)
        self.lbl_progreso.configure(text="")

    def actualizar_estado(self):
        """Cambia textos y botones según la carpeta esté bloqueada o abierta."""
        if self.carpeta is None:
            return
        if es_caja_cerrada(self.carpeta):
            self.lbl_estado.configure(text="🔒 Carpeta BLOQUEADA", text_color="#e74c3c")
            self.btn_accion.configure(text="Desbloquear", state="normal",
                                      fg_color=COLOR_DESBLOQUEAR[0], hover_color=COLOR_DESBLOQUEAR[1])
            self.marco_confirmar.pack_forget()
            self.btn_abrir.configure(state="disabled")
        else:
            self.lbl_estado.configure(text="🔓 Carpeta abierta (sin proteger)", text_color="#2ecc71")
            self.btn_accion.configure(text="Bloquear carpeta", state="normal",
                                      fg_color=COLOR_BLOQUEAR[0], hover_color=COLOR_BLOQUEAR[1])
            # La confirmación va justo debajo de la contraseña
            self.marco_confirmar.pack(fill="x", padx=18, after=self.ent_pass)
            self.btn_abrir.configure(state="normal")

    def abrir_carpeta(self):
        if self.carpeta:
            abrir_en_explorador(self.carpeta)

    def al_cerrar(self):
        if self.ocupado:
            messagebox.showinfo("Espera un momento", "Se está procesando la carpeta. Cierra cuando termine.")
            return
        self.destroy()

    # Lo que pasa al darle al botón principal   
    def accion(self):
        if self.carpeta is None or self.ocupado:
            return
        password = self.ent_pass.get()

        if es_caja_cerrada(self.carpeta):
            #   DESBLOQUEAR  
            if not password:
                messagebox.showwarning("Falta la contraseña", "Escribe la contraseña para desbloquear.")
                return
            self.iniciar(desbloquear, password, "✔ Carpeta desbloqueada")
        else:
            #   BLOQUEAR (valido la contraseña primero)  
            if len(password) < MIN_PASSWORD:
                messagebox.showwarning("Contraseña muy corta", f"Usa mínimo {MIN_PASSWORD} caracteres.")
                return
            if password != self.ent_confirmar.get():
                messagebox.showwarning("No coinciden", "La contraseña y su confirmación son diferentes.")
                return
            if not messagebox.askyesno(
                    "Confirmar",
                    "Se van a cifrar todos los archivos de esta carpeta.\n\n"
                    "Si olvidas la contraseña NO podrás recuperarlos.\n\n¿Continuar?"):
                return
            self.iniciar(bloquear, password, "✔ Carpeta bloqueada")

    def iniciar(self, funcion, password, mensaje_ok):
        """Corre la operación en un hilo aparte para que la ventana no se congele."""
        self.ocupado = True
        self.btn_accion.configure(state="disabled")
        self.barra.set(0)
        self.lbl_progreso.configure(text="Procesando... (la primera parte puede tardar un segundo)")

        def trabajo():
            try:
                funcion(self.carpeta, password,
                        lambda hechos, total, nombre: self.cola.put(("progreso", hechos, total, nombre)))
                self.cola.put(("ok", mensaje_ok))
            except ErrorCaja as e:
                self.cola.put(("error", str(e)))
            except Exception as e:
                self.cola.put(("error", f"Error inesperado: {e}"))

        threading.Thread(target=trabajo, daemon=True).start()
        self.after(100, self.revisar_cola)

    def revisar_cola(self):
        """Lee los avisos del hilo de trabajo y actualiza la barra y los mensajes."""
        terminado = False
        while not self.cola.empty():
            msg = self.cola.get()
            if msg[0] == "progreso":
                _, hechos, total, nombre = msg
                self.barra.set(hechos / total)
                self.lbl_progreso.configure(text=f"{hechos}/{total}  {nombre}")
            elif msg[0] == "ok":
                self.barra.set(1)
                self.lbl_progreso.configure(text=msg[1])
                terminado = True
            elif msg[0] == "error":
                self.barra.set(0)
                self.lbl_progreso.configure(text="")
                messagebox.showerror("Error", msg[1])
                terminado = True

        if terminado:
            self.ocupado = False
            self.ent_pass.delete(0, "end")        # no dejo la contraseña escrita en pantalla
            self.ent_confirmar.delete(0, "end")
            self.actualizar_estado()
        else:
            self.after(100, self.revisar_cola)


# Iniciar el programa.
if __name__ == "__main__":
    App().mainloop()