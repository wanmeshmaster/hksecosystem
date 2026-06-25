import os
from flask import Flask, render_template

app = Flask(__name__, static_folder='source', static_url_path='/source')

@app.route('/')
def home():
    # We added the HKS Bank app here with the ID 'hks-bank'
    apps = [
        {
            'id': 'coming-soon', 
            'title': 'Coming soon...', 
            'url': '/coming-soon.html'
        },
        {
            'id': 'hks-bank', 
            'title': 'HKS Bank', 
            'url': '/hks-bank.html'
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

    return render_template('index.html', apps=apps)

@app.route('/coming-soon.html')
def coming_soon():
    return render_template('coming-soon.html')

# New route for the HKS Bank template
@app.route('/hks-bank.html')
def hks_bank():
    return render_template('hks-bank.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True) # Assuming you changed it to 8080