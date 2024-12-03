FROM alerta/alerta-web

# Копирование плагина
COPY --chown=alerta:alerta ./plugins/alerta_oauth2_oidc /tmp/alerta_oauth2_oidc

# Установка плагина
RUN /venv/bin/pip install /tmp/alerta_oauth2_oidc && \
    rm -rf /tmp/alerta_oauth2_oidc

# Запуск Alerta
CMD ["alertad", "run", "--host", "0.0.0.0", "--port", "8080"]