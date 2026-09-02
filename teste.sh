#!/bin/bash

start="${1:-*}"

case "$start" in
    0)
        echo "Opcao 0"
        ;;
    1)
        echo "Opcao 1"
        ;;
    2)
        echo "Saindo..."
        ;;
    *)
        echo "Opcao invalida"
        ;;
esac