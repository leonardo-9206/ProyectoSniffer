# Packet Sniffer - Redes

Proyecto final para la materia de Redes. Este es un sniffer de paquetes escrito en C++ que captura tráfico de red en tiempo real y muestra los datos en una interfaz gráfica interactiva.

## Requisitos Previos
- **Sistema Operativo**: Windows
- **Compilador**: MinGW (`g++` compatible con C++17)
- **Npcap**: Necesitas instalar [Npcap](https://npcap.com/) en tu computadora para que el programa pueda leer las tarjetas de red físicas.

## Librerías Utilizadas
- **Npcap (Libpcap para Windows)**: El motor principal que atrapa los paquetes físicos.
- **Dear ImGui**: Librería súper ligera para crear la interfaz gráfica.
- **GLFW y OpenGL3**: Herramientas necesarias para poder renderizar la ventana de ImGui y los gráficos.

## Cómo Compilar
Como el proyecto ya incluye la carpeta `.vscode` preconfigurada, simplemente abre la carpeta del proyecto en Visual Studio Code y presiona:
`Ctrl + Shift + B`
Esto generará automáticamente el ejecutable usando el compilador global `g++`.

## Cómo Ejecutar
Una vez que compile sin errores, el ejecutable estará en la carpeta `build/sniffer.exe`. 
**IMPORTANTE:** Tienes que correr el programa como **Administrador**. Si no eres administrador, Npcap te va a rechazar el permiso para "escuchar" la tarjeta de red y el sniffer no atrapará tráfico.
