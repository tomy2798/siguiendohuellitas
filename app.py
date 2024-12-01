import os
from flask import Flask, render_template, request, redirect, url_for, abort,flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from pymongo import MongoClient
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from flask_caching import Cache
import secrets
import base64  
 
app = Flask(__name__)
port = int(os.environ.get('PORT', 5000))
app.secret_key = secrets.token_hex(16)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'




# Conexión a MongoDB
client = MongoClient('mongodb+srv://tomasdelgadopro:hks3G7zSDQXMqEky@mascotas.886jd.mongodb.net/')
db = client['siguiendohuellitas']
dogs_collection = db['mascotas']
users_collection = db['users']

###Login
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']


@login_manager.user_loader
def load_user(user_id):
    user_data = users_collection.find_one({'_id': ObjectId(user_id)})
    return User(user_data) if user_data else None

def generate_secure_token():
    """Genera un token seguro para edición"""
    return secrets.token_urlsafe(32)

# Login Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user_data = users_collection.find_one({'username': username})
        
        if user_data and check_password_hash(user_data['password'], password):
            user = User(user_data)
            login_user(user)
            flash('¡Inicio de sesión exitoso!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Credenciales inválidas', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        # Check if username already exists
        existing_user = users_collection.find_one({'username': username})
        if existing_user:
            flash('El nombre de usuario ya existe', 'error')
            return redirect(url_for('register'))
        
        # Hash the password
        hashed_password = generate_password_hash(password)
        
        # Insert new user
        users_collection.insert_one({
            'username': username,
            'password': hashed_password,
            'email': email
        })
        
        flash('Registro exitoso. Por favor, inicia sesión.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión exitosamente', 'success')
    return redirect(url_for('login'))

cache = Cache(app, config={
    'CACHE_TYPE': 'simple',
    'CACHE_DEFAULT_TIMEOUT': 300  # 5 minutos
})

@app.route('/admin')
@login_required
def index():
    # Obtener el número de página actual desde la solicitud
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Número de registros por página
    
    # Calcular el desplazamiento
    skip = (page - 1) * per_page
    
    # Contar total de registros 
    total_registrations = dogs_collection.count_documents({})
    
    # Calcular número total de páginas
    total_pages = (total_registrations + per_page - 1) // per_page
    
    # Usar proyección para recuperar solo los campos necesarios
    dog_registrations = list(dogs_collection.find(
        {}, 
        {
            'dog_name': 1, 
            'owner_name': 1, 
            'owner_email': 1, 
            'phone': 1,
            'edit_token': 1,
            'is_completed': 1
        }
    ).sort('_id', -1).skip(skip).limit(per_page))
    
    # Convertir ObjectId a string para serialización
    for dog in dog_registrations:
        dog['_id'] = str(dog['_id'])
    
    return render_template('admin.html', 
                           dogs=dog_registrations, 
                           current_page=page, 
                           total_pages=total_pages)
    
    
@app.route('/delete_dog/<id>', methods=['POST'])
@login_required
def delete_dog(id):
    try:
        # Eliminar el registro del perro
        result = dogs_collection.delete_one({'_id': ObjectId(id)})
        
        if result.deleted_count > 0:
            return jsonify({'status': 'success', 'message': 'Registro eliminado exitosamente'}), 200
        else:
            return jsonify({'status': 'error', 'message': 'No se encontró el registro'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500







##############################




def generate_secure_token():
    """Genera un token seguro para edición"""
    return secrets.token_urlsafe(32)

@app.route('/create_links', methods=['POST'])
def create_links():
    owner_name = request.form['owner_name']
    owner_email = request.form['owner_email']
    
    # Generar un ID único
    unique_id = str(ObjectId())
    
    # Generar un token seguro para edición
    edit_token = generate_secure_token()
    
    # Crear los enlaces
    edit_link = f"/edit/{unique_id}/{edit_token}"
    view_link = f"/view/{unique_id}"
    
    # Guardar documento inicial con el token de edición
    dogs_collection.insert_one({
        '_id': ObjectId(unique_id),
        'owner_name': owner_name,
        'owner_email': owner_email,
        'edit_token': edit_token,
        'is_completed': False  # Para saber si los datos del perro ya fueron añadidos
    })
    
    # Solo mostrar el link de edición en la interfaz de administrador
    return render_template('admin_links.html', 
                         edit_link=edit_link, 
                         view_link=view_link,
                         owner_email=owner_email)

@app.route('/edit/<id>/<token>', methods=['GET', 'POST'])
def edit(id, token):
    # Verificar que el documento existe y el token es correcto
    dog_data = dogs_collection.find_one({
        '_id': ObjectId(id),
        'edit_token': token
    })
    
    if not dog_data:
        abort(403)  # Forbidden - Token inválido o documento no existe
    
    if request.method == 'POST':
        # Manejar la foto de perfil
        profile_pic = request.files.get('profile_pic')
        profile_pic_data = None
            # Leer la imagen y codificarla en base64
        profile_pic_data = base64.b64encode(profile_pic.read()).decode('utf-8')
        
        # Actualizar datos en MongoDB
        update_data = {
            'dog_name': request.form['dog_name'],
            'address': request.form['address'],
            'phone': request.form['phone'],
            'owner_name': request.form['owner_name'],
            'owner_email': request.form['owner_email'],
            'neighborhood': request.form['neighborhood'],
            'province': request.form['province'], 
            'dog_description': request.form['dog_description'],
            'is_completed': True
        }
        
        # Si hay foto de perfil, agregarla a los datos de actualización
        if profile_pic_data:
            update_data['profile_pic'] = profile_pic_data
        
        dogs_collection.update_one(
            {'_id': ObjectId(id), 'edit_token': token},
            {'$set': update_data}
        )
        return redirect(url_for('view', id=id))
    
    return render_template('edit.html', dog=dog_data, id=id, token=token)


@app.route('/view/<id>')
def view(id):
    dog_data = dogs_collection.find_one({'_id': ObjectId(id)})
    if not dog_data:
        abort(404)
    return render_template('view.html', dog=dog_data)

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', 
                         message="No tienes permiso para editar este registro"), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', 
                         message="El registro no fue encontrado"), 404
    
    
def create_indexes():
    # Crear índices para consultas frecuentes
    dogs_collection.create_index([('is_completed', 1)])
    users_collection.create_index([('username', 1)], unique=True)


if __name__ == '__main__':
    create_indexes()
    app.run(host='0.0.0.0', port=port)