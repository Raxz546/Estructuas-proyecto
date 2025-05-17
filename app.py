from flask import Flask, render_template, request, redirect, url_for, session, abort
import json
import os
import bcrypt
from functools import wraps
from uuid import uuid4
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta'

USUARIOS_FILE = 'usuarios.json'

# Usuarios fijos admins y owners (sin registro, solo login)
USUARIOS_FIJOS = {
    "valerie": {"nombre": "Valerie", "contraseña": bcrypt.hashpw(b"valerie123", bcrypt.gensalt()).decode('utf-8'), "rol": "admin"},
    "bolagay": {"nombre": "Bolagay", "contraseña": bcrypt.hashpw(b"bolagay123", bcrypt.gensalt()).decode('utf-8'), "rol": "admin"},
    "gabriel": {"nombre": "Gabriel", "contraseña": bcrypt.hashpw(b"gabriel123", bcrypt.gensalt()).decode('utf-8'), "rol": "admin"},
    "raxz": {"nombre": "Raxz", "contraseña": bcrypt.hashpw(b"raxz123", bcrypt.gensalt()).decode('utf-8'), "rol": "owner"},
}

data_por_usuario = {}
UPLOAD_FOLDER = os.path.join('static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def cargar_usuarios():
    if not os.path.exists(USUARIOS_FILE):
        return []
    with open(USUARIOS_FILE, 'r') as f:
        return json.load(f)

def guardar_usuarios(usuarios):
    with open(USUARIOS_FILE, 'w') as f:
        json.dump(usuarios, f, indent=4)

def role_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'loggedin' not in session:
                return redirect(url_for('login'))
            if session.get('rol') not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return wrapper

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        usuario = request.form['usuario'].lower()
        contraseña = request.form['contraseña']

        # Primero revisar usuarios fijos (admin/owner)
        if usuario in USUARIOS_FIJOS:
            hash_guardado = USUARIOS_FIJOS[usuario]['contraseña'].encode('utf-8')
            if bcrypt.checkpw(contraseña.encode('utf-8'), hash_guardado):
                session['loggedin'] = True
                session['username'] = usuario
                session['nombre'] = USUARIOS_FIJOS[usuario]['nombre']
                session['rol'] = USUARIOS_FIJOS[usuario]['rol']
                return redirect(url_for('dashboard'))

        # Luego revisar usuarios registrados (role=user)
        usuarios = cargar_usuarios()
        user = next((u for u in usuarios if u['usuario'] == usuario), None)
        if user:
            hash_guardado = user['contraseña'].encode('utf-8')
            if bcrypt.checkpw(contraseña.encode('utf-8'), hash_guardado):
                session['loggedin'] = True
                session['username'] = usuario
                session['nombre'] = user['nombre']
                session['rol'] = 'user'
                return redirect(url_for('dashboard'))

        error = "Usuario o contraseña incorrectos"

    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        usuario = request.form['usuario'].lower()
        nombre = request.form['nombre']
        contraseña = request.form['contraseña']

        # Verificar que no sea usuario fijo ni ya exista en registrados
        if usuario in USUARIOS_FIJOS:
            error = "El usuario está reservado y no se puede registrar."
        else:
            usuarios = cargar_usuarios()
            if any(u['usuario'] == usuario for u in usuarios):
                error = "El usuario ya está registrado."
            else:
                hashed = bcrypt.hashpw(contraseña.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                usuarios.append({
                    "usuario": usuario,
                    "nombre": nombre,
                    "contraseña": hashed
                })
                guardar_usuarios(usuarios)
                return redirect(url_for('login'))

    return render_template('register.html', error=error)

@app.route('/dashboard')
@role_required('user', 'admin', 'owner')
def dashboard():
    return render_template('dashboard.html', nombre=session['nombre'], rol=session['rol'])

@app.route('/usuarios')
@role_required('admin', 'owner')
def usuarios_view():
    usuarios_registrados = cargar_usuarios()
    fijos = [
        {"usuario": u, "nombre": info["nombre"], "rol": info["rol"]}
        for u, info in USUARIOS_FIJOS.items()
    ]
    todos = fijos + [{"usuario": u["usuario"], "nombre": u["nombre"], "rol": "user"} for u in usuarios_registrados]

    return render_template('usuarios.html', usuarios=todos, rol=session['rol'])


@app.route('/editar/<usuario>', methods=['GET', 'POST'])
@role_required('user', 'admin', 'owner')
def editar_usuario(usuario):
    usuarios = cargar_usuarios()
    rol_actual = session['rol']
    usuario_actual = session['username']

    # 1. Buscar si es usuario fijo
    if usuario in USUARIOS_FIJOS:
        if usuario != usuario_actual and rol_actual != 'owner':
            abort(403)  # Solo owner puede editar fijos que no sean él mismo
        editable = USUARIOS_FIJOS[usuario]
        origen = 'fijo'
    else:
        editable = next((u for u in usuarios if u['usuario'] == usuario), None)
        origen = 'json'

    if not editable:
        return "Usuario no encontrado", 404

    if usuario != usuario_actual and rol_actual == 'user':
        abort(403)  # users no pueden editar a otros

    if request.method == 'POST':
        nuevo_nombre = request.form['nombre']
        nueva_contraseña = request.form['contraseña']
        
        if nueva_contraseña:
            hashed = bcrypt.hashpw(nueva_contraseña.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        else:
            hashed = editable['contraseña']

        if origen == 'fijo':
            USUARIOS_FIJOS[usuario]['nombre'] = nuevo_nombre
            USUARIOS_FIJOS[usuario]['contraseña'] = hashed
        else:
            for u in usuarios:
                if u['usuario'] == usuario:
                    u['nombre'] = nuevo_nombre
                    u['contraseña'] = hashed
            guardar_usuarios(usuarios)

        # Si se edita el propio nombre, actualizarlo en la sesión
        if usuario == usuario_actual:
            session['nombre'] = nuevo_nombre

        return redirect(url_for('usuarios_view') if rol_actual != 'user' else url_for('dashboard'))

    return render_template('editar.html', usuario=usuario, nombre=editable['nombre'])


@app.route('/datos/<usuario>', methods=['GET', 'POST'])
@role_required('user', 'admin', 'owner')
def gestionar_datos(usuario):
    usuario_actual = session['username']
    rol = session['rol']

    if usuario != usuario_actual and rol == 'user':
        abort(403)

    if usuario not in data_por_usuario:
        data_por_usuario[usuario] = {"textos": [], "imagenes": [], "tablas": []}

    if request.method == 'POST':
        tipo = request.form.get('tipo')

        if tipo == 'texto':
            texto = request.form.get('contenido')
            if texto:
                data_por_usuario[usuario]['textos'].append({
                    "id": str(uuid4()),
                    "contenido": texto
                })

        elif tipo == 'imagen':
            imagen = request.files.get('imagen')
            if imagen:
                filename = secure_filename(imagen.filename)
                path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                imagen.save(path)
                print(f"Imagen guardada en: {path}")  # <-- para debug
                data_por_usuario[usuario]['imagenes'].append({
                    "id": str(uuid4()),
                    "contenido": filename
                })

        elif tipo == 'tabla':
            tabla = request.form.get('contenido_tabla')
            if tabla:
                data_por_usuario[usuario]['tablas'].append({
                    "id": str(uuid4()),
                    "contenido": tabla
                })


    datos = data_por_usuario.get(usuario, {"textos": [], "imagenes": [], "tablas": []})

    return render_template("datos.html", datos=datos, usuario=usuario, rol=rol) 

@app.route('/eliminar/<usuario>/<tipo>/<id>', methods=['POST'])
@role_required('user', 'admin', 'owner')
def eliminar_dato(usuario, tipo, id):
    usuario_actual = session['username']
    rol = session['rol']

    # Solo los usuarios normales no pueden eliminar datos de otros usuarios
    if usuario != session['username'] and session['rol'] == 'user':
        abort(403)

    if usuario in data_por_usuario and tipo in data_por_usuario[usuario]:
        data_por_usuario[usuario][tipo] = [
            d for d in data_por_usuario[usuario][tipo] if d['id'] != id
        ]

    return redirect(url_for('gestionar_datos', usuario=usuario))


@app.route('/editar_dato/<usuario>/<tipo>/<id>', methods=['GET', 'POST'])
@role_required('user', 'admin', 'owner')
def editar_dato(usuario, tipo, id):
    usuario_actual = session['username']
    rol = session['rol']

    if usuario != usuario_actual and rol == 'user':
        abort(403)

    # Usar get para evitar error si el usuario no tiene datos aún
    item = next((d for d in data_por_usuario.get(usuario, {}).get(tipo, []) if d['id'] == id), None)
    if not item:
        return "Dato no encontrado", 404

    if request.method == 'POST':
        nuevo_contenido = request.form['contenido']
        item['contenido'] = nuevo_contenido
        return redirect(url_for('gestionar_datos', usuario=usuario))

    return render_template('editar_dato.html', tipo=tipo, dato=item, usuario=usuario)



@app.route('/eliminar_usuario/<usuario>', methods=['POST'])
@role_required('owner')
def eliminar_usuario(usuario):
    if usuario in USUARIOS_FIJOS:
        return "No puedes eliminar un usuario fijo", 403

    usuarios = cargar_usuarios()
    usuarios = [u for u in usuarios if u['usuario'] != usuario]
    guardar_usuarios(usuarios)

    # También limpiamos los datos temporales si existían
    if usuario in data_por_usuario:
        del data_por_usuario[usuario]

    return redirect(url_for('usuarios_view'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)