from flask import Flask, render_template, jsonify, send_file, url_for
import subprocess
import os

app = Flask(__name__, static_folder="static", template_folder="templates")

# Ensure static and templates directories exist
os.makedirs("static", exist_ok=True)
os.makedirs("templates", exist_ok=True)

# Move the uploaded image to the static directory safely
image_path = "static/Cybersecurity.jpeg"
original_image = "Cybersecurity protection.jpeg"

if os.path.exists(original_image) and not os.path.exists(image_path):
    os.rename(original_image, image_path)

# HTML content as a string
html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tracescape</title>
    <style>
        body {
            background: url('{{ url_for("static", filename="Cybersecurity.jpeg") }}') no-repeat center center fixed;
            background-size: cover;
            color: red;
            font-family: Arial, sans-serif;
            text-align: center;
            margin-top: 50px;
        }
        button {
            background-color: red;
            color: white;
            border: none;
            padding: 10px 20px;
            font-size: 20px;
            cursor: pointer;
            border-radius: 5px;
        }
        button:hover {
            background-color: darkred;
        }
    </style>
</head>
<body>
    <h1>Tracescape - Network Packet Capture</h1>
    <button onclick="startCapture()">Start Packet Capture</button>
    <p id="status"></p>

    <script>
        function startCapture() {
            document.getElementById("status").innerText = "Capturing packets...";
            fetch("/capture")
                .then(response => response.json())
                .then(data => {
                    document.getElementById("status").innerText = data.message;
                    if (data.kml) {
                        let link = document.createElement("a");
                        link.href = data.kml;
                        link.innerText = "Download KML File";
                        link.style.display = "block";
                        link.style.marginTop = "20px";
                        link.style.color = "yellow";
                        link.style.fontSize = "18px";
                        document.body.appendChild(link);
                    }
                });
        }
    </script>
</body>
</html>
"""

# Write the HTML content to the index.html file
with open("templates/index.html", "w") as f:
    f.write(html_content)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/capture")
def capture():
    try:
        print("[INFO] Starting packet capture with pcap.py...")
        result = subprocess.run(["python", "pcap.py"], check=True, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("[ERROR] pcap.py stderr:", result.stderr)

        print("[INFO] Processing packets with main.py...")
        result = subprocess.run(["python", "main.py"], check=True, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("[ERROR] main.py stderr:", result.stderr)

        kml_path = "network_tracking.kml"

        if os.path.exists(kml_path):
            return jsonify({"message": "Capture complete! Download the KML file.", "kml": "/download-kml"})
        else:
            return jsonify({"message": "KML file not found!"})
    except subprocess.CalledProcessError as e:
        print("[ERROR] Subprocess execution failed:", e.stderr)
        return jsonify({"message": f"Error: {e.stderr}"})
    except Exception as e:
        print("[ERROR] Unexpected error:", str(e))
        return jsonify({"message": f"Unexpected error: {str(e)}"})

@app.route("/download-kml")
def download_kml():
    kml_path = "network_tracking.kml"
    if os.path.exists(kml_path):
        return send_file(kml_path, as_attachment=True)
    else:
        return jsonify({"message": "KML file not found!"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
