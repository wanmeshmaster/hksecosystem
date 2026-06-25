import os
from flask import Flask, render_template

# Initialize Flask and tell it to serve static files from the 'source' folder
app = Flask(__name__, static_folder='source', static_url_path='/source')

@app.route('/')
def home():
    # The 'id' will be used to look for the .jpg file.
    apps = [
        {
            'id': 'coming-soon', 
            'title': 'Coming soon...', 
            'url': '/coming-soon.html'
        }
    ]
    
    # Check if a background image exists for each app
    for a in apps:
        image_filename = f"{a['id']}.jpg"
        image_path = os.path.join(app.root_path, 'source', image_filename)
        
        if os.path.exists(image_path):
            a['bg_image'] = image_filename
        else:
            a['bg_image'] = None

    # Pass the apps list to the HTML template
    return render_template('index.html', apps=apps)

@app.route('/coming-soon.html')
def coming_soon():
    return render_template('coming-soon.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)