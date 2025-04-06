from flask import Flask, jsonify, request, render_template

# Initialize the Flask application
app = Flask(__name__)

# Home route (returns a welcome message)
@app.route('/')
def home():
    return "Welcome to the Flask App!"

# JSON response route (returns a JSON response)
@app.route('/api')
def api():
    return jsonify({
        "message": "This is a simple API response",
        "status": "success"
    })

# Route with a dynamic parameter
@app.route('/hello/<name>')
def hello(name):
    return f"Hello, {name}!"

# Form submission route (GET and POST)
@app.route('/submit', methods=['GET', 'POST'])
def submit():
    if request.method == 'POST':
        # Get data from the form
        user_name = request.form['name']
        return f"Form submitted! Hello, {user_name}."
    return '''
        <form method="POST">
            Name: <input type="text" name="name">
            <input type="submit" value="Submit">
        </form>
    '''

# Render a simple HTML page with the render_template function (requires an HTML file in the templates folder)
@app.route('/about')
def about():
    return render_template('about.html')

# Run the application
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
