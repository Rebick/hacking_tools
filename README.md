# hacking_tools
Aqui pondre mis herramientas de hackeo que vaya creando
 1. El archivo Doc2.doc, es un word que al abrirlo y habilitar las macros intentará ejecutar los archivos de prueba  que intentan ejecutar el cmd.exe
 2. El archivo test.hta abre un cmd usando el navegador, este se prueba al final por que es el más efectivo para ejecutarlo direcatamente en caso de que no se puedan ejecutar las macros.
 3. Para la prueba de archivos vdb podemos usar  compiladores, el cscript.exe y wscript
 4. Para la prueba de archivos vsb, se puede utilizar el mismo archivo, pero con extension .txt y se ejecutará como "wscript /e:VBScript c:\Users\thm\Desktop\payload.txt"
 5. Para la prueba del archvio powershell, primero debemos ver las politicas de ps
    Get-ExecutionPolicy
    #Si el resultado es restricted, podemos cambiarlas con el comando siguiente
    Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
    #Para hacer un bypass a la restriccion podemos usar el comando
    powershell -ex bypass -File thm.ps1
