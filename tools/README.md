# Herramientas de publicación

`firmar_actualizacion.py` firma con Ed25519 un manifiesto vinculado a un ZIP de un único archivo `VOLVE_Centro_Proteccion.exe`. Requiere Python y el paquete `cryptography`.

La clave PRIVADA se conserva fuera de este repositorio. No agregarla a Git, Issues, Releases ni logs.

Solo publicar actualizaciones del panel previamente probadas en Windows x64; validar la firma y el SHA-256 antes de anunciar la versión.
