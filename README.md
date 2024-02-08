# hacking_tools

Aqui pondre mis herramientas de hackeo que vaya creando.

1. **Doc2.doc**: Este archivo es un documento de Word que, al abrirlo y habilitar las macros, intentará ejecutar los archivos de prueba que buscan ejecutar el `cmd.exe`.

2. **test.hta**: Este archivo HTA abre un cmd usando el navegador. Se prueba al final porque es el método más efectivo para ejecutarlo directamente en caso de que no se puedan ejecutar las macros.

3. Para la prueba de archivos VDB, podemos utilizar compiladores, el `cscript.exe` y `wscript`.

4. Para la prueba de archivos VSB, se puede utilizar el mismo archivo, pero con extensión `.txt`, y se ejecutará como `wscript /e:VBScript c:\Users\thm\Desktop\payload.txt`.

5. Para la prueba del archivo PowerShell, primero debemos ver las políticas de PowerShell:
   ```powershell
   Get-ExecutionPolicy

Si el resultado es restricted, podemos cambiarlas con el siguiente comando:

powershell

Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

Para hacer un bypass a la restricción, podemos usar el comando:

powershell

powershell -ex bypass -File thm.ps1

6. kali_conf.sh: Este archivo es un script de configuración (hardening) para Kali en la nube. Cambia la contraseña del usuario kali, activa el autenticador de Google para SSH y RDP, activa el firewall y prohíbe comportamientos anómalos. Además, guarda los registros de estas actividades.
