from flask import Flask, render_template

app = Flask(__name__)

# Route for the main portal page
@app.route('/')
def home():
    return render_template('index.html')

# Route for the coming soon app slot
@app.route('/coming-soon.html')
def coming_soon():
    return render_template('coming-soon.html')

if __name__ == '__main__':
    # host='0.0.0.0' exposes the server to your local network
    # port=5000 is the default, but you can change it if needed
    # debug=True allows the server to auto-reload if you make code changes
    app.run(host='0.0.0.0', port=5000, debug=True)