
# 1. Start with a pristine, lightweight Linux environment
FROM python:3.11-slim

# 2. Install the C++ ExifTool engine
RUN apt-get update && apt-get install -y exiftool

# 3. Create a folder for your app inside the server
WORKDIR /app

# 4. Copy your requirements and install Flask/Gunicorn
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# 5. Copy your app.py, index.html, and everything else
COPY . .

# 6. Turn the engine on and bind it to the public internet
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:10000", "app:app"]
