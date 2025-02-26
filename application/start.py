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
            margin-top: 20px;
        }
        button:hover {
            background-color: darkred;
        }
        #download-kml-btn {
            background: linear-gradient(135deg, #00feba, #5b548a);
            border: none;
            padding: 15px 30px;
            font-size: 18px;
            font-weight: bold;
            color: white;
            cursor: pointer;
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0, 255, 255, 0.4);
            transition: all 0.3s ease-in-out;
            text-transform: uppercase;
            letter-spacing: 1px;
            display: none; /* Initially hidden */
        }
        #download-kml-btn:hover {
            background: linear-gradient(135deg, #5b548a, #00feba);
            box-shadow: 0 6px 20px rgba(0, 255, 255, 0.6);
        }
    </style>
</head>
<body>
    <h1>Tracescape - Network Packet Capture</h1>
    <button onclick="startCapture()">Start Packet Capture</button>
    <p id="status"></p>

    <button id="download-kml-btn" onclick="downloadKML()">Download KML File</button>

    <script>
        function startCapture() {
            document.getElementById("status").innerText = "Capturing packets...";
            fetch("/capture")
                .then(response => response.json())
                .then(data => {
                    document.getElementById("status").innerText = data.message;
                    if (data.kml) {
                        let downloadBtn = document.getElementById("download-kml-btn");
                        downloadBtn.style.display = "inline-block";
                        downloadBtn.setAttribute("data-url", data.kml);
                    }
                });
        }

        function downloadKML() {
            let downloadBtn = document.getElementById("download-kml-btn");
            let kmlUrl = downloadBtn.getAttribute("data-url");
            if (kmlUrl) {
                window.location.href = kmlUrl;
            } else {
                alert("KML file not available.");
            }
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
