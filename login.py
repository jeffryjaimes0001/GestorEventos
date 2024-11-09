from flask import Flask, request, render_template, redirect, url_for, session, flash
import firebase_admin
from firebase_admin import credentials, firestore
import hashlib

# Configuración de Flask y Firebase
app = Flask(__name__)
app.secret_key = "clave_secreta_para_sesiones"

# Inicializar Firebase
cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

# Función para obtener el hash de una contraseña
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Ruta de inicio de sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hashed = hash_password(password)

        # Buscar el usuario en Firestore
        users_ref = db.collection('usuarios')
        query = users_ref.where('username', '==', username).where('password', '==', password_hashed).stream()

        # Verificar si se encontró un usuario
        for user in query:
            session['user'] = username
            flash("Inicio de sesión exitoso", "success")
            return redirect(url_for('welcome'))

        flash("Usuario o contraseña incorrectos", "error")
        return redirect(url_for('login'))
    return render_template('login.html')

# Ruta de bienvenida después del login
@app.route('/welcome')
def welcome():
    if 'user' in session:
        return f"Bienvenido, {session['user']}!"
    else:
        return redirect(url_for('login'))

# Ruta de cierre de sesión
@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Has cerrado sesión", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
