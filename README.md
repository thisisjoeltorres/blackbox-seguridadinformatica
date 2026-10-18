# 🔐 Caja Fuerte

Aplicación en Python que convierte cualquier carpeta en una **caja fuerte protegida con contraseña**. Al bloquearla, todo su contenido (archivos, subcarpetas y hasta los nombres) queda cifrado. Al desbloquearla con la contraseña correcta, todo vuelve a su lugar y se puede trabajar normal: copiar, pegar, cortar, modificar, etc.

Proyecto desarrollado para la asignatura de **Seguridad Informática**. Funciona en **Windows, macOS y Linux**.

---

## ✨ Características

- Interfaz gráfica moderna (modo oscuro) hecha con `customtkinter`.
- Cifrado **AES-256-GCM** con la biblioteca `cryptography`.
- La contraseña se convierte en clave con **scrypt** y un *salt* aleatorio.
- Cifra **nombres de archivos y estructura de carpetas**, no solo el contenido.
- Funciona con archivos grandes: cifra por pedazos de 1 MB sin llenar la memoria.
- Detecta si un archivo cifrado fue modificado o está dañado.
- Seguro ante fallos: los archivos originales solo se borran cuando todo ya quedó cifrado.
- Validación de datos: contraseña mínima de 8 caracteres, confirmación y aviso antes de bloquear.
- Barra de progreso y proceso en segundo plano (la ventana no se congela).

---

## 📦 Requisitos

- Python 3.9 o superior (en macOS, el instalador de [python.org](https://www.python.org) ya trae tkinter).
- Dependencias:

```bash
pip install cryptography customtkinter
```

---

## 🚀 Uso

```bash
python caja_fuerte.py
```

1. Pulsa **Elegir** y selecciona la carpeta.
2. La app te dice si está 🔓 **abierta** o 🔒 **bloqueada**.
3. **Para bloquear:** escribe una contraseña, confírmala y pulsa **Bloquear carpeta**.
4. **Para desbloquear:** escribe la contraseña y pulsa **Desbloquear**.
5. El botón **Abrir carpeta** la abre en el Explorador o el Finder.

> ⚠️ **Si olvidas la contraseña, los archivos no se pueden recuperar.** No existe ninguna puerta trasera.

---

## 🧠 Cómo funciona

### Al bloquear

1. Se lista el contenido de la carpeta (los accesos directos/symlinks se ignoran).
2. Se genera un *salt* aleatorio y se deriva la clave de 256 bits con **scrypt** (`n=2^15, r=8, p=1`).
3. Cada archivo se cifra con **AES-GCM** en pedazos de 1 MB. Cada pedazo usa un *nonce* distinto (prefijo aleatorio de 8 bytes + contador de 4 bytes). El último pedazo se marca como tal para detectar archivos cortados.
4. Cada archivo cifrado se guarda con un **nombre aleatorio** y extensión `.enc`.
5. La lista de nombres y rutas originales se cifra y se guarda en `caja_fuerte.meta` junto con el *salt* y los parámetros de scrypt.
6. Solo si todo salió bien, se borran los archivos originales.

### Al desbloquear

1. Se lee `caja_fuerte.meta` y se deriva la clave con la contraseña ingresada.
2. Se intenta abrir la lista de archivos. Si la contraseña es incorrecta, **GCM falla y no se toca nada**.
3. Se recrean las subcarpetas y se descifra cada archivo a su ruta original.
4. Si algo falla, se limpian los archivos restaurados y la carpeta sigue bloqueada.
5. Si todo sale bien, se eliminan los `.enc` y el archivo de control.

### Cómo se ve una carpeta bloqueada

```
mi_carpeta/
├── 307050c918f92a7d.enc
├── 737f564882a4f6b4.enc
├── 7814880045942d2b.enc
└── caja_fuerte.meta
```

No se ven nombres, tipos de archivo ni estructura.

---

## 🔑 Manejo de claves y vectores de inicialización

| Elemento | Qué es | Dónde se guarda |
|---|---|---|
| Contraseña | Lo que escribe el usuario | En ningún lado |
| Salt (16 bytes) | Valor aleatorio que hace única la derivación de la clave | En `caja_fuerte.meta` (no es secreto) |
| Clave AES (32 bytes) | Resultado de scrypt(contraseña, salt) | Solo en memoria mientras se usa |
| Nonce / IV (12 bytes) | Prefijo aleatorio + contador por cada pedazo | Dentro de cada archivo `.enc` (no es secreto) |
| Etiqueta GCM (16 bytes) | Verifica que nada fue alterado | Al final de cada pedazo cifrado |

---

## ⚠️ Limitaciones

- **Sin contraseña no hay recuperación.**
- Mientras la carpeta está **desbloqueada**, los archivos están en claro en el disco. La protección es solo cuando está bloqueada.
- Borrar los originales no es un borrado seguro: en discos SSD pueden quedar restos recuperables. Para información muy sensible, usa además cifrado de disco completo (BitLocker en Windows, FileVault en macOS).
- El programa no protege contra un equipo ya infectado (por ejemplo, un *keylogger* que capture la contraseña).
- No se pueden bloquear discos completos ni la carpeta personal del usuario (protección contra errores).
- Los accesos directos (symlinks) dentro de la carpeta no se cifran.

---

## 🧪 Pruebas realizadas

La lógica de cifrado se probó con:

- Carpeta con subcarpetas anidadas y una subcarpeta vacía.
- Archivo vacío, archivo de exactamente 1 MB y archivo de más de 2 MB.
- Texto con ñ, tildes y signos especiales.
- Contraseña incorrecta (se rechaza sin modificar nada).
- Archivo cifrado alterado (se detecta y la carpeta queda bloqueada y limpia).
- Verificación SHA-256: todos los archivos se recuperan idénticos al original.

---

## 📁 Empaquetar como ejecutable (opcional)

Se hace en cada sistema por separado:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed caja_fuerte.py
```

Genera un `.exe` en Windows y una aplicación en macOS (dentro de la carpeta `dist/`).

---

## 🛠️ Tecnologías

- [Python](https://www.python.org)
- [cryptography](https://cryptography.io) (AES-GCM y scrypt)
- [customtkinter](https://github.com/TomSchimansky/CustomTkinter) (interfaz gráfica)

---

## 👤 Autor

Joel Torres · Universidad de Pamplona · Seguridad Informática