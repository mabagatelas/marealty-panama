// ============================================
// BACKEND MAREALTY PANAMA - Node.js + Express
// ============================================

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// Middleware
app.use(helmet());

// CORS restrictivo
const clientUrl = process.env.CLIENT_URL || 'http://localhost:8000';
const corsOptions = {
    origin: clientUrl,
    credentials: true,
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // límite de requests
  message: JSON.stringify({ error: 'Demasiadas solicitudes, intenta más tarde' })
});
app.use('/api/', limiter);

// Conexión MongoDB
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/marealty_pa';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB Conectado a:', MONGODB_URI.substring(0, 40) + '...'))
.catch(err => console.error('❌ Error de conexión a MongoDB:', err.message));


// ============================================
// MODELOS
// ============================================

// models/Property.js
const PropertySchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  price: { type: Number, required: true, min: 0 },
  location: {
    address: String,
    city: String, // Distrito/Corregimiento (San Francisco, David, etc.)
    province: String, // Provincia (Panamá, Chiriquí, Colón)
    postalCode: String,
    coordinates: { lat: Number, lng: Number }
  },
  type: {
    type: String,
    enum: ['Piso', 'Casa', 'Ático', 'Loft', 'Estudio', 'Chalet'],
    required: true
  },
  features: {
    rooms: { type: Number, min: 0 },
    bathrooms: { type: Number, min: 0 },
    size: { type: Number, min: 0 },
    floor: Number,
    hasElevator: Boolean,
    hasParking: Boolean,
    hasStorage: Boolean,
    hasTerrace: Boolean,
    hasPool: Boolean
  },
  yearBuilt: Number,
  energyRating: { type: String, enum: ['A', 'B', 'C', 'D', 'E', 'F', 'G'] },
  amenities: [String],
  description: { type: String, maxLength: 2000 },
  images: [{ url: String, caption: String, order: Number }],
  status: { type: String, enum: ['available', 'reserved', 'sold', 'rented'], default: 'available' },
  featured: { type: Boolean, default: false },
  agent: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
const Property = mongoose.model('Property', PropertySchema);

// models/User.js
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true, minLength: 6 },
  role: { type: String, enum: ['client', 'agent', 'admin'], default: 'client' },
  profile: { phone: String, avatar: String, bio: String },
  favorites: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Property' }],
  lastLogin: Date,
  createdAt: { type: Date, default: Date.now }
});

// Hash password antes de guardar
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// Métodos del usuario
UserSchema.methods.comparePassword = async function(password) {
  return bcrypt.compare(password, this.password);
};

UserSchema.methods.generateToken = function() {
  return jwt.sign(
    { id: this._id, role: this.role },
    process.env.JWT_SECRET || 'secret',
    { expiresIn: '30d' }
  );
};
const User = mongoose.model('User', UserSchema);

// models/Mortgage.js (Esquema simplificado solo para referencia en seed)
const MortgageSchema = new mongoose.Schema({
    bank: String,
    rate: Number,
    maxLTV: Number,
    term: Number
});
const Mortgage = mongoose.model('Mortgage', MortgageSchema);


// ============================================
// MIDDLEWARE DE AUTENTICACIÓN
// ============================================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token no proporcionado' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'secret', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido o expirado' });
    }
    req.user = user;
    next();
  });
};

const authorizeRole = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'No tienes permisos para esta acción' });
    }
    next();
  };
};

// ============================================
// RUTAS - PROPIEDADES
// ============================================

const propertyRouter = express.Router();

// GET - Obtener todas las propiedades con filtros
propertyRouter.get('/', async (req, res) => {
  try {
    const { type, city, minPrice, maxPrice } = req.query;

    const query = { status: 'available' }; // Por defecto solo disponibles
    
    // Aplicar filtro por tipo de propiedad
    if (type) query.type = type;

    // Aplicar filtro de búsqueda por ciudad (Distrito/Corregimiento) o provincia
    if (city) {
        query.$or = [
            { 'location.city': new RegExp(city, 'i') },
            { 'location.province': new RegExp(city, 'i') }
        ];
    }
    
    // Aplicar filtro de precio máximo
    if (maxPrice) {
        query.price = { $lte: Number(maxPrice) };
    }

    const properties = await Property
      .find(query)
      .sort('-featured -createdAt'); // Destacados primero

    res.json({ success: true, data: properties });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET - Obtener propiedad por ID
propertyRouter.get('/:id', async (req, res) => {
  try {
    const property = await Property.findById(req.params.id);
    if (!property) {
      return res.status(404).json({ error: 'Propiedad no encontrada' });
    }
    res.json({ success: true, data: property });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST - Crear nueva propiedad (solo agentes y admin)
propertyRouter.post('/', authenticateToken, authorizeRole('agent', 'admin'), async (req, res) => {
  try {
    const property = new Property({
      ...req.body,
      agent: req.user.id
    });

    await property.save();
    res.status(201).json({ success: true, data: property });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// DELETE - Eliminar propiedad (solo admin)
propertyRouter.delete('/:id', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    const result = await Property.findByIdAndDelete(req.params.id);
    if (!result) {
        return res.status(404).json({ error: 'Propiedad no encontrada' });
    }
    res.json({ success: true, message: 'Propiedad eliminada' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// RUTAS - USUARIOS Y AUTENTICACIÓN
// ============================================

const userRouter = express.Router();

// POST - Login
userRouter.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    user.lastLogin = Date.now();
    await user.save();

    const token = user.generateToken();

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        favorites: user.favorites
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET - Perfil del usuario (usado para auto-login)
userRouter.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User
      .findById(req.user.id)
      .select('-password'); // Excluir password

    res.json({ success: true, data: user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST - Añadir a favoritos
userRouter.post('/favorites/:propertyId', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (!user.favorites.includes(req.params.propertyId)) {
      user.favorites.push(req.params.propertyId);
      await user.save();
    }

    res.json({ success: true, favorites: user.favorites });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE - Quitar de favoritos
userRouter.delete('/favorites/:propertyId', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    user.favorites = user.favorites.filter(
      fav => fav.toString() !== req.params.propertyId
    );
    await user.save();

    res.json({ success: true, favorites: user.favorites });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// CONFIGURACIÓN DE RUTAS
// ============================================

app.use('/api/properties', propertyRouter);
app.use('/api/users', userRouter);

// Ruta de health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    app: 'Marealty Panama API',
    environment: process.env.NODE_ENV || 'development'
  });
});

// Manejo de errores 404
app.use((req, res) => {
  res.status(404).json({ error: 'Ruta no encontrada' });
});


// ============================================
// INICIALIZACIÓN DEL SERVIDOR
// ============================================

const PORT = process.env.PORT || 3001;

// Seeders
const seedDatabase = async () => {
  try {
    // Limpiar base de datos
    await Property.deleteMany({});
    await User.deleteMany({});
    await Mortgage.deleteMany({});

    // Crear usuario admin
    const admin = new User({
      name: 'Admin Marealty',
      email: 'admin@marealty.com',
      password: 'admin123',
      role: 'admin'
    });
    await admin.save();

    // Crear agente
    const agent = new User({
      name: 'Carlos Mendoza (Agente)',
      email: 'carlos@marealty.com',
      password: 'agent123',
      role: 'agent',
      profile: {
        phone: '+507 6000 1234',
      }
    });
    await agent.save();

    // Crear cliente
    const client = new User({
      name: 'Cliente Demo',
      email: 'cliente@demo.com',
      password: 'demo123',
      role: 'client',
    });
    await client.save();

    // Crear propiedades (Adaptadas a Panamá)
    const properties = [
      {
        title: 'Apartamento de Lujo en San Francisco',
        price: 450000,
        location: {
          address: 'Vía Porras 10',
          city: 'San Francisco', // Corregimiento
          province: 'Panamá', // Provincia
          postalCode: '0819'
        },
        type: 'Piso',
        features: { rooms: 3, bathrooms: 3, size: 140, floor: 15, hasElevator: true, hasPool: true },
        description: 'Exclusivo apartamento con vistas al mar y acabados de lujo, en el corazón de la Ciudad de Panamá.',
        status: 'available',
        featured: true,
        agent: agent._id,
        images: [{ url: "https://placehold.co/400x200/a02020/ffffff?text=SAN+FRANCISCO+LUJO" }],
        amenities: ["Piscina", "Gimnasio", "Seguridad 24h", "Balcón"]
      },
      {
        title: 'Casa unifamiliar con jardín en La Chorrera',
        price: 185000,
        location: {
          address: 'Calle Principal, El Coco',
          city: 'La Chorrera', // Distrito
          province: 'Panamá Oeste', // Provincia
          postalCode: '0701'
        },
        type: 'Casa',
        features: { rooms: 4, bathrooms: 2, size: 250, hasParking: true },
        description: 'Amplia casa ideal para familias en una zona tranquila de Panamá Oeste, cerca de comercios.',
        status: 'available',
        featured: true,
        agent: agent._id,
        images: [{ url: "https://placehold.co/400x200/800000/ffffff?text=LA+CHORRERA+FAMILIAR" }],
        amenities: ["Jardín Grande", "Garaje", "Cercana a escuelas"]
      },
      {
        title: 'Penthouse moderno en Bella Vista',
        price: 680000,
        location: {
          address: 'Avenida Balboa',
          city: 'Bella Vista', // Corregimiento
          province: 'Panamá', // Provincia
          postalCode: '0816'
        },
        type: 'Ático',
        features: { rooms: 2, bathrooms: 2, size: 90, hasTerrace: true },
        description: 'Ático con terraza privada y vistas panorámicas a la Cinta Costera. Perfecto para ejecutivos.',
        status: 'reserved',
        featured: false,
        agent: agent._id,
        images: [{ url: "https://placehold.co/400x200/a02020/ffffff?text=BELLA+VISTA+VISTAS" }],
        amenities: ["Terraza", "Ascensor", "Seguridad 24h"]
      },
      {
        title: 'Finca con vista a la montaña en Boquete',
        price: 320000,
        location: {
          address: 'Alto Lino',
          city: 'Boquete', // Distrito
          province: 'Chiriquí', // Provincia
          postalCode: '0403'
        },
        type: 'Chalet',
        features: { rooms: 3, bathrooms: 2, size: 180, hasParking: true },
        description: 'Propiedad única con clima fresco y vistas espectaculares, ideal para retiro o inversión turística.',
        status: 'available',
        featured: false,
        agent: agent._id,
        images: [{ url: "https://placehold.co/400x200/800000/ffffff?text=BOQUETE+MONTAÑA" }],
        amenities: ["Clima fresco", "Chimenea", "Vistas Panorámicas"]
      },
      {
        title: 'Estudio renovado en El Cangrejo',
        price: 130000,
        location: {
          address: 'Vía Argentina',
          city: 'El Cangrejo', // Corregimiento
          province: 'Panamá', // Provincia
          postalCode: '0820'
        },
        type: 'Estudio',
        features: { rooms: 1, bathrooms: 1, size: 55, hasElevator: true },
        description: 'Estudio céntrico, ideal para estudiantes o solteros. Cerca de estaciones de metro y universidades.',
        status: 'available',
        featured: true,
        agent: agent._id,
        images: [{ url: "https://placehold.co/400x200/a02020/ffffff?text=EL+CANGREJO+ESTUDIO" }],
        amenities: ["Metro Cerca", "Aire acondicionado central"]
      },
    ];

    await Property.insertMany(properties);
    
    // Asignar favoritos al cliente demo
    client.favorites.push(properties[0]._id, properties[2]._id);
    await client.save();

    console.log('✅ Base de datos MAREALTY inicializada con datos de prueba de Panamá.');
  } catch (error) {
    console.error('❌ Error al inicializar la base de datos:', error.message);
  }
};


app.listen(PORT, () => {
  console.log(`
    🏠 MAREALTY Backend API
    =====================
    🚀 Servidor corriendo en puerto ${PORT}
    🔧 Ambiente: ${process.env.NODE_ENV || 'development'}
  `);

  // Ejecutar seeder si es necesario
  if (process.env.SEED_DB === 'true') {
    seedDatabase();
  }
});

module.exports = app;