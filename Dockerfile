FROM alerta/alerta-web

# Копирование плагина
COPY --chown=alerta:alerta ./plugins/alerta_oauth2_oidc /tmp/alerta_oauth2_oidc

# Установка плагина
RUN pip install /tmp/alerta_oauth2_oidc && \
    rm -rf /tmp/alerta_oauth2_oidc

# Копируем настройки и добавляем их в alertad.conf
COPY --chown=alerta:alerta ./alertad.conf /app/alertad.conf

# Запуск Alerta
CMD ["alertad", "run", "--host", "0.0.0.0"]