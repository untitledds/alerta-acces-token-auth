FROM alerta/alerta-web

# Установка зависимостей
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

# Копирование плагина
COPY alerta_oauth2_oidc /app/alerta_oauth2_oidc

# Установка плагина
RUN pip install /app/alerta_oauth2_oidc

# Копируем настройки и добавляем их в alertad.conf
COPY --chown=alerta:alerta ./alertad.conf /app/alertad.conf

# Запуск Alerta
CMD ["alertad", "run", "--host", "0.0.0.0"]