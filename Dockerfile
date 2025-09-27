FROM python:3.11-slim

# Installation des dépendances système
RUN apt-get update && apt-get install -y \
    openssh-client \
    sshpass \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Création du répertoire de travail
WORKDIR /app

# Copie des fichiers requirements
COPY requirements.txt .

# Installation des dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code source
COPY . .

# Création du répertoire pour les données persistantes
RUN mkdir -p /app/data

# Exposition du port
EXPOSE 5000

# Variable d'environnement pour Flask
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Commande de démarrage
CMD ["python", "app.py"]