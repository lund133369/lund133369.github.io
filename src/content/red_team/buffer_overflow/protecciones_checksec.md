---
title: "PROTECCIONES - CHECKSEC BIN"
description: "PROTECCIONES - CHECKSEC BIN , Explicacio de tipos de protecciones de los binarios"
published: true
pubDate: "2024-06-01"
updatedDate: "2024-06-01"
heroImage: /assets/red_team/buffer_overflow/buffer_1/20241026033304.png
---
### Resumen de Configuraciones de Seguridad

1. **Canary Deshabilitado**:
    - **Descripción**: El mecanismo de **stack canaries** (canarios) es una protección que se utiliza para detectar desbordamientos de buffer en la pila. Si está deshabilitado, significa que no se está utilizando este mecanismo de protección.
    - **Implicaciones**: Aumenta el riesgo de que un atacante pueda sobrescribir el retorno de la pila y ejecutar código malicioso sin ser detectado.
2. **NX Deshabilitado**:
    - **Descripción**: **NX (No-eXecute)** es una protección que impide la ejecución de código en áreas de memoria que deberían ser solo de datos. Si está deshabilitado, el binario permite la ejecución de código en cualquier área de memoria.
    - **Implicaciones**: Facilita ataques como la inyección de código, ya que el atacante puede ejecutar código en la pila o en el heap.
3. **PIE Habilitado**:
    - **Descripción**: **PIE (Position Independent Executable)** permite que el binario se cargue en direcciones de memoria aleatorias, aprovechando ASLR (Address Space Layout Randomization).
    - **Implicaciones**: Mejora la seguridad al dificultar que los atacantes predigan la ubicación de las funciones y variables, haciendo más complicado explotar vulnerabilidades.
4. **Fortify Deshabilitado**:
    - **Descripción**: **Fortify Source** es una técnica que agrega protecciones a las funciones de la biblioteca estándar de C, como `strcpy` y `sprintf`, para ayudar a prevenir vulnerabilidades comunes. Si está deshabilitado, esas protecciones no se aplican.
    - **Implicaciones**: Incrementa la vulnerabilidad del binario a ataques de desbordamiento de buffer y otros tipos de exploit relacionados con la manipulación de cadenas.
5. **RELRO Full Habilitado**:
    - **Descripción**: **RELRO (RELocation Read-Only)** es una protección que hace que las secciones de datos que contienen direcciones de función sean de solo lectura después de que el binario ha sido cargado. **Full RELRO** significa que se utilizan las protecciones completas.
    - **Implicaciones**: Ayuda a proteger contra ataques que intentan modificar la tabla de direcciones de funciones (GOT), aumentando la seguridad del binario.
