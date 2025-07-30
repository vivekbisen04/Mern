# MERN Stack Interview Preparation Sheet

## JavaScript Fundamentals

### 1. Variables and Scope
**Concept**: Variable declarations and their accessibility in different scopes.

```javascript
// var - function scoped, can be redeclared
var name = "John";
var name = "Jane"; // OK

// let - block scoped, cannot be redeclared
let age = 25;
// let age = 30; // Error

// const - block scoped, cannot be reassigned
const PI = 3.14;
// PI = 3.15; // Error
```

### 2. Arrow Functions
**Concept**: Shorter syntax for functions with lexical `this` binding.

```javascript
// Regular function
function add(a, b) {
    return a + b;
}

// Arrow function
const add = (a, b) => a + b;

// With single parameter
const square = x => x * x;

// With multiple statements
const greet = name => {
    const message = `Hello, ${name}!`;
    return message;
};
```

### 3. Destructuring
**Concept**: Extract values from arrays or objects into variables.

```javascript
// Array destructuring
const numbers = [1, 2, 3];
const [first, second] = numbers;

// Object destructuring
const person = { name: "John", age: 30 };
const { name, age } = person;

// Function parameter destructuring
const displayUser = ({ name, email }) => {
    console.log(`${name}: ${email}`);
};
```

### 4. Template Literals
**Concept**: Enhanced string literals with embedded expressions.

```javascript
const name = "John";
const age = 30;

// Template literal
const message = `Hello, my name is ${name} and I'm ${age} years old.`;

// Multi-line strings
const html = `
    <div>
        <h1>${name}</h1>
        <p>Age: ${age}</p>
    </div>
`;
```

### 5. Promises and Async/Await
**Concept**: Handle asynchronous operations.

```javascript
// Promise
const fetchData = () => {
    return new Promise((resolve, reject) => {
        setTimeout(() => {
            resolve("Data fetched");
        }, 1000);
    });
};

// Using async/await
const getData = async () => {
    try {
        const data = await fetchData();
        console.log(data);
    } catch (error) {
        console.error(error);
    }
};
```

### 6. Spread and Rest Operators
**Concept**: Spread expands elements, rest collects them.

```javascript
// Spread operator
const arr1 = [1, 2, 3];
const arr2 = [...arr1, 4, 5]; // [1, 2, 3, 4, 5]

const obj1 = { a: 1, b: 2 };
const obj2 = { ...obj1, c: 3 }; // { a: 1, b: 2, c: 3 }

// Rest operator
const sum = (...numbers) => {
    return numbers.reduce((total, num) => total + num, 0);
};
```

### 7. Array Methods
**Concept**: Higher-order functions for array manipulation.

```javascript
const numbers = [1, 2, 3, 4, 5];

// map - transform elements
const doubled = numbers.map(n => n * 2);

// filter - select elements
const evens = numbers.filter(n => n % 2 === 0);

// reduce - accumulate values
const sum = numbers.reduce((acc, n) => acc + n, 0);

// find - locate element
const found = numbers.find(n => n > 3);
```

### 8. Closures
**Concept**: Functions that have access to outer scope variables.

```javascript
const createCounter = () => {
    let count = 0;
    
    return {
        increment: () => ++count,
        decrement: () => --count,
        getCount: () => count
    };
};

const counter = createCounter();
console.log(counter.increment()); // 1
console.log(counter.getCount()); // 1
```

---

## MongoDB

### 1. Basic CRUD Operations
**Concept**: Create, Read, Update, Delete operations in MongoDB.

```javascript
// Using Mongoose
const mongoose = require('mongoose');

// Schema definition
const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    age: Number
});

const User = mongoose.model('User', userSchema);

// Create
const newUser = new User({ name: "John", email: "john@email.com", age: 30 });
await newUser.save();

// Read
const users = await User.find({ age: { $gte: 18 } });
const user = await User.findById(userId);

// Update
await User.findByIdAndUpdate(userId, { age: 31 });

// Delete
await User.findByIdAndDelete(userId);
```

### 2. Schema and Models
**Concept**: Define data structure and validation rules.

```javascript
const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        maxlength: 100
    },
    price: {
        type: Number,
        required: true,
        min: 0
    },
    category: {
        type: String,
        enum: ['electronics', 'clothing', 'books']
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const Product = mongoose.model('Product', productSchema);
```

### 3. Population (Joins)
**Concept**: Reference documents from other collections.

```javascript
const authorSchema = new mongoose.Schema({
    name: String,
    email: String
});

const postSchema = new mongoose.Schema({
    title: String,
    content: String,
    author: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Author'
    }
});

// Populate author data
const posts = await Post.find().populate('author');
```

---

## Express.js

### 1. Basic Server Setup
**Concept**: Create HTTP server with routing capabilities.

```javascript
const express = require('express');
const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.get('/', (req, res) => {
    res.json({ message: 'Hello World!' });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
```

### 2. Route Parameters and Query Strings
**Concept**: Extract data from URL paths and query parameters.

```javascript
// Route parameters
app.get('/users/:id', (req, res) => {
    const userId = req.params.id;
    res.json({ userId });
});

// Query parameters
app.get('/search', (req, res) => {
    const { q, page = 1, limit = 10 } = req.query;
    res.json({ query: q, page, limit });
});

// Multiple parameters
app.get('/users/:id/posts/:postId', (req, res) => {
    const { id, postId } = req.params;
    res.json({ userId: id, postId });
});
```

### 3. Middleware
**Concept**: Functions that execute during request-response cycle.

```javascript
// Custom middleware
const logger = (req, res, next) => {
    console.log(`${req.method} ${req.url} - ${new Date().toISOString()}`);
    next();
};

// Authentication middleware
const authenticate = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    // Verify token logic here
    next();
};

app.use(logger);
app.use('/protected', authenticate);
```

### 4. Error Handling
**Concept**: Handle errors in Express applications.

```javascript
// Error handling middleware
const errorHandler = (err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ 
        error: 'Something went wrong!',
        message: err.message 
    });
};

// Async error wrapper
const asyncHandler = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

// Usage
app.get('/users', asyncHandler(async (req, res) => {
    const users = await User.find();
    res.json(users);
}));

app.use(errorHandler);
```

### 5. RESTful API Routes
**Concept**: Design API endpoints following REST conventions.

```javascript
const express = require('express');
const router = express.Router();

// GET /api/users - Get all users
router.get('/', async (req, res) => {
    const users = await User.find();
    res.json(users);
});

// GET /api/users/:id - Get user by ID
router.get('/:id', async (req, res) => {
    const user = await User.findById(req.params.id);
    res.json(user);
});

// POST /api/users - Create user
router.post('/', async (req, res) => {
    const user = new User(req.body);
    await user.save();
    res.status(201).json(user);
});

// PUT /api/users/:id - Update user
router.put('/:id', async (req, res) => {
    const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(user);
});

// DELETE /api/users/:id - Delete user
router.delete('/:id', async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.status(204).send();
});

app.use('/api/users', router);
```

---

## React

### 1. Functional Components
**Concept**: Components as functions that return JSX.

```jsx
// Basic functional component
const Welcome = ({ name }) => {
    return <h1>Hello, {name}!</h1>;
};

// With destructuring and default props
const UserCard = ({ name = "Guest", email, age }) => {
    return (
        <div className="user-card">
            <h2>{name}</h2>
            <p>Email: {email}</p>
            <p>Age: {age}</p>
        </div>
    );
};
```

### 2. useState Hook
**Concept**: Add state to functional components.

```jsx
import { useState } from 'react';

const Counter = () => {
    const [count, setCount] = useState(0);
    const [name, setName] = useState('');

    const increment = () => setCount(count + 1);
    const decrement = () => setCount(prev => prev - 1);

    return (
        <div>
            <h2>Count: {count}</h2>
            <button onClick={increment}>+</button>
            <button onClick={decrement}>-</button>
            
            <input 
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Enter name"
            />
        </div>
    );
};
```

### 3. useEffect Hook
**Concept**: Handle side effects and lifecycle events.

```jsx
import { useState, useEffect } from 'react';

const UserProfile = ({ userId }) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);

    // Mount and dependency update
    useEffect(() => {
        const fetchUser = async () => {
            setLoading(true);
            try {
                const response = await fetch(`/api/users/${userId}`);
                const userData = await response.json();
                setUser(userData);
            } catch (error) {
                console.error('Error:', error);
            } finally {
                setLoading(false);
            }
        };

        fetchUser();
    }, [userId]); // Dependency array

    // Cleanup effect
    useEffect(() => {
        const timer = setInterval(() => {
            console.log('Timer running');
        }, 1000);

        return () => clearInterval(timer); // Cleanup
    }, []);

    if (loading) return <div>Loading...</div>;
    
    return (
        <div>
            <h1>{user?.name}</h1>
            <p>{user?.email}</p>
        </div>
    );
};
```

### 4. Event Handling
**Concept**: Handle user interactions in React.

```jsx
const FormExample = () => {
    const [formData, setFormData] = useState({
        name: '',
        email: '',
        message: ''
    });

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: value
        }));
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        console.log('Form submitted:', formData);
    };

    const handleReset = () => {
        setFormData({ name: '', email: '', message: '' });
    };

    return (
        <form onSubmit={handleSubmit}>
            <input
                name="name"
                value={formData.name}
                onChange={handleChange}
                placeholder="Name"
            />
            <input
                name="email"
                value={formData.email}
                onChange={handleChange}
                placeholder="Email"
            />
            <textarea
                name="message"
                value={formData.message}
                onChange={handleChange}
                placeholder="Message"
            />
            <button type="submit">Submit</button>
            <button type="button" onClick={handleReset}>Reset</button>
        </form>
    );
};
```

### 5. Conditional Rendering
**Concept**: Show different content based on conditions.

```jsx
const UserDashboard = ({ user, isLoggedIn }) => {
    return (
        <div>
            {/* Conditional rendering with && */}
            {isLoggedIn && <h1>Welcome back, {user.name}!</h1>}
            
            {/* Conditional rendering with ternary */}
            {isLoggedIn ? (
                <div>
                    <p>Dashboard content</p>
                    <button>Logout</button>
                </div>
            ) : (
                <div>
                    <p>Please log in</p>
                    <button>Login</button>
                </div>
            )}
            
            {/* Multiple conditions */}
            {user.role === 'admin' && isLoggedIn && (
                <div>Admin Panel</div>
            )}
        </div>
    );
};
```

### 6. Lists and Keys
**Concept**: Render dynamic lists of elements.

```jsx
const TodoList = ({ todos }) => {
    return (
        <ul>
            {todos.map(todo => (
                <li key={todo.id} className={todo.completed ? 'completed' : ''}>
                    <span>{todo.text}</span>
                    <button onClick={() => toggleTodo(todo.id)}>
                        {todo.completed ? 'Undo' : 'Complete'}
                    </button>
                </li>
            ))}
        </ul>
    );
};

// With filtering
const FilteredList = ({ items, filter }) => {
    const filteredItems = items.filter(item => 
        item.name.toLowerCase().includes(filter.toLowerCase())
    );

    return (
        <div>
            {filteredItems.length > 0 ? (
                filteredItems.map(item => (
                    <div key={item.id}>{item.name}</div>
                ))
            ) : (
                <p>No items found</p>
            )}
        </div>
    );
};
```

### 7. Props and PropTypes
**Concept**: Pass data between components with type checking.

```jsx
import PropTypes from 'prop-types';

const ProductCard = ({ product, onAddToCart, discount = 0 }) => {
    const finalPrice = product.price * (1 - discount);

    return (
        <div className="product-card">
            <h3>{product.name}</h3>
            <p>${finalPrice.toFixed(2)}</p>
            <button onClick={() => onAddToCart(product.id)}>
                Add to Cart
            </button>
        </div>
    );
};

ProductCard.propTypes = {
    product: PropTypes.shape({
        id: PropTypes.number.isRequired,
        name: PropTypes.string.isRequired,
        price: PropTypes.number.isRequired
    }).isRequired,
    onAddToCart: PropTypes.func.isRequired,
    discount: PropTypes.number
};
```

---

## Node.js

### 1. Modules and Exports
**Concept**: Organize code into reusable modules.

```javascript
// math.js - Named exports
const add = (a, b) => a + b;
const subtract = (a, b) => a - b;

module.exports = { add, subtract };

// Or ES6 modules
export const add = (a, b) => a + b;
export const subtract = (a, b) => a - b;

// user.js - Default export
class User {
    constructor(name, email) {
        this.name = name;
        this.email = email;
    }
}

module.exports = User;
// Or ES6: export default User;

// main.js - Importing
const { add, subtract } = require('./math');
const User = require('./user');

// Or ES6
import { add, subtract } from './math.js';
import User from './user.js';
```

### 2. File System Operations
**Concept**: Read and write files using Node.js fs module.

```javascript
const fs = require('fs').promises;
const path = require('path');

// Read file
const readFile = async (filename) => {
    try {
        const data = await fs.readFile(filename, 'utf8');
        return data;
    } catch (error) {
        console.error('Error reading file:', error);
    }
};

// Write file
const writeFile = async (filename, data) => {
    try {
        await fs.writeFile(filename, data, 'utf8');
        console.log('File written successfully');
    } catch (error) {
        console.error('Error writing file:', error);
    }
};

// Check if file exists
const fileExists = async (filename) => {
    try {
        await fs.access(filename);
        return true;
    } catch {
        return false;
    }
};
```

### 3. Environment Variables
**Concept**: Configure applications using environment variables.

```javascript
// Using dotenv package
require('dotenv').config();

const config = {
    port: process.env.PORT || 3000,
    dbUrl: process.env.DATABASE_URL || 'mongodb://localhost:27017/myapp',
    jwtSecret: process.env.JWT_SECRET || 'default-secret',
    nodeEnv: process.env.NODE_ENV || 'development'
};

// .env file
/*
PORT=3000
DATABASE_URL=mongodb://localhost:27017/myapp
JWT_SECRET=your-secret-key
NODE_ENV=development
*/

module.exports = config;
```

### 4. NPM and Package Management
**Concept**: Manage project dependencies and scripts.

```json
// package.json
{
  "name": "my-app",
  "version": "1.0.0",
  "description": "MERN stack application",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "jest",
    "build": "npm run build:client && npm run build:server"
  },
  "dependencies": {
    "express": "^4.18.0",
    "mongoose": "^6.0.0",
    "dotenv": "^16.0.0"
  },
  "devDependencies": {
    "nodemon": "^2.0.0",
    "jest": "^28.0.0"
  }
}
```

```bash
# NPM commands
npm install                    # Install all dependencies
npm install express           # Install specific package
npm install -D nodemon        # Install as dev dependency
npm start                     # Run start script
npm run dev                   # Run custom script
npm test                      # Run tests
```

---

## Advanced Concepts

### 1. JWT Authentication
**Concept**: JSON Web Tokens for stateless authentication.

```javascript
const jwt = require('jsonwebtoken');

// Generate token
const generateToken = (userId) => {
    return jwt.sign({ userId }, 'secret', { expiresIn: '7d' });
};

// Login route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (user && await bcrypt.compare(password, user.password)) {
        const token = generateToken(user._id);
        res.json({ token, user });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// JWT Middleware
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token' });
    }
    
    jwt.verify(token, 'secret', (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.userId = decoded.userId;
        next();
    });
};

// Protected route
app.get('/profile', authenticateToken, async (req, res) => {
    const user = await User.findById(req.userId);
    res.json(user);
});
```

### 2. Advanced Async/Await Patterns
**Concept**: Handle multiple asynchronous operations efficiently.

```javascript
// Parallel execution
const fetchUserData = async (userId) => {
    const [user, posts, comments] = await Promise.all([
        User.findById(userId),
        Post.find({ author: userId }),
        Comment.find({ author: userId })
    ]);
    return { user, posts, comments };
};

// Sequential with error handling
const processUser = async (userData) => {
    try {
        const hashedPassword = await bcrypt.hash(userData.password, 10);
        const user = await User.create({ ...userData, password: hashedPassword });
        await sendWelcomeEmail(user.email);
        return user;
    } catch (error) {
        throw new Error(`User processing failed: ${error.message}`);
    }
};

// Retry mechanism
const fetchWithRetry = async (url, maxRetries = 3) => {
    for (let i = 0; i < maxRetries; i++) {
        try {
            const response = await fetch(url);
            return await response.json();
        } catch (error) {
            if (i === maxRetries - 1) throw error;
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }
};
```

### 3. Input Validation
**Concept**: Validate and sanitize user input.

```javascript
const Joi = require('joi');

// Validation schema
const userSchema = Joi.object({
    name: Joi.string().min(2).max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(8).required(),
    age: Joi.number().integer().min(18).max(120)
});

// Validation middleware
const validateUser = (req, res, next) => {
    const { error } = userSchema.validate(req.body);
    if (error) {
        return res.status(400).json({ error: error.details[0].message });
    }
    next();
};

// Usage
app.post('/users', validateUser, async (req, res) => {
    const user = new User(req.body);
    await user.save();
    res.status(201).json(user);
});
```

### 4. File Upload Handling
**Concept**: Handle file uploads with multer.

```javascript
const multer = require('multer');

const storage = multer.diskStorage({
    destination: 'uploads/',
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ 
    storage,
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

// Single file upload
app.post('/upload', upload.single('avatar'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    res.json({ filename: req.file.filename });
});

// Multiple files
app.post('/upload-multiple', upload.array('photos', 5), (req, res) => {
    const filenames = req.files.map(file => file.filename);
    res.json({ filenames });
});
```

### 5. Database Transactions
**Concept**: Ensure data consistency with transactions.

```javascript
// Basic transaction
const transferMoney = async (fromId, toId, amount) => {
    const session = await mongoose.startSession();
    
    try {
        session.startTransaction();
        
        await User.findByIdAndUpdate(fromId, { $inc: { balance: -amount } }, { session });
        await User.findByIdAndUpdate(toId, { $inc: { balance: amount } }, { session });
        
        await session.commitTransaction();
        return { success: true };
    } catch (error) {
        await session.abortTransaction();
        throw error;
    } finally {
        session.endSession();
    }
};
```

### 6. Rate Limiting and Security
**Concept**: Protect APIs from abuse.

```javascript
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

// Security headers
app.use(helmet());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests'
});

app.use('/api/', limiter);

// Strict rate limit for sensitive routes
const authLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5,
    message: 'Too many login attempts'
});

app.use('/api/login', authLimiter);
```

### 7. Caching Strategies
**Concept**: Improve performance with caching.

```javascript
const cache = new Map();

// Simple memory cache
const getCachedData = async (key, fetchFunction) => {
    if (cache.has(key)) {
        return cache.get(key);
    }
    
    const data = await fetchFunction();
    cache.set(key, data);
    return data;
};

// Cache middleware
const cacheMiddleware = (duration = 300) => {
    return (req, res, next) => {
        const key = req.originalUrl;
        const cached = cache.get(key);
        
        if (cached) {
            return res.json(cached);
        }
        
        const originalJson = res.json;
        res.json = function(data) {
            cache.set(key, data);
            setTimeout(() => cache.delete(key), duration * 1000);
            originalJson.call(this, data);
        };
        
        next();
    };
};

// Usage
app.get('/api/products', cacheMiddleware(600), async (req, res) => {
    const products = await Product.find();
    res.json(products);
});
```

### 8. React Context API
**Concept**: Manage global state without prop drilling.

```jsx
import { createContext, useContext, useReducer } from 'react';

const AuthContext = createContext();

const authReducer = (state, action) => {
    switch (action.type) {
        case 'LOGIN':
            return { ...state, user: action.payload, isAuthenticated: true };
        case 'LOGOUT':
            return { ...state, user: null, isAuthenticated: false };
        default:
            return state;
    }
};

export const AuthProvider = ({ children }) => {
    const [state, dispatch] = useReducer(authReducer, {
        user: null,
        isAuthenticated: false
    });

    const login = (userData) => {
        dispatch({ type: 'LOGIN', payload: userData });
    };

    const logout = () => {
        dispatch({ type: 'LOGOUT' });
    };

    return (
        <AuthContext.Provider value={{ ...state, login, logout }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within AuthProvider');
    }
    return context;
};

// Usage
const Dashboard = () => {
    const { user, isAuthenticated, logout } = useAuth();
    
    return (
        <div>
            {isAuthenticated ? (
                <>
                    <h1>Welcome, {user.name}!</h1>
                    <button onClick={logout}>Logout</button>
                </>
            ) : (
                <p>Please login</p>
            )}
        </div>
    );
};
```

### 9. Custom React Hooks
**Concept**: Reusable stateful logic.

```jsx
import { useState, useEffect } from 'react';

// Custom hook for API calls
const useApi = (url) => {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchData = async () => {
            try {
                setLoading(true);
                const response = await fetch(url);
                const result = await response.json();
                setData(result);
            } catch (err) {
                setError(err.message);
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, [url]);

    return { data, loading, error };
};

// Custom hook for form handling
const useForm = (initialValues) => {
    const [values, setValues] = useState(initialValues);

    const handleChange = (name, value) => {
        setValues(prev => ({ ...prev, [name]: value }));
    };

    const reset = () => setValues(initialValues);

    return { values, handleChange, reset };
};

// Usage
const UserList = () => {
    const { data: users, loading, error } = useApi('/api/users');
    const { values, handleChange } = useForm({ name: '', email: '' });

    if (loading) return <div>Loading...</div>;
    if (error) return <div>Error: {error}</div>;

    return (
        <div>
            <input
                value={values.name}
                onChange={(e) => handleChange('name', e.target.value)}
                placeholder="Name"
            />
            {users.map(user => (
                <div key={user._id}>{user.name}</div>
            ))}
        </div>
    );
};
```

### 10. Error Boundaries
**Concept**: Catch and handle React component errors.

```jsx
import { Component } from 'react';

class ErrorBoundary extends Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false };
    }

    static getDerivedStateFromError(error) {
        return { hasError: true };
    }

    componentDidCatch(error, errorInfo) {
        console.error('Error caught:', error, errorInfo);
    }

    render() {
        if (this.state.hasError) {
            return (
                <div>
                    <h2>Something went wrong!</h2>
                    <button onClick={() => window.location.reload()}>
                        Reload Page
                    </button>
                </div>
            );
        }

        return this.props.children;
    }
}

// Usage
const App = () => {
    return (
        <ErrorBoundary>
            <Header />
            <MainContent />
            <Footer />
        </ErrorBoundary>
    );
};
```

### 11. WebSocket Implementation
**Concept**: Real-time communication.

```javascript
// Server-side (Socket.io)
const io = require('socket.io')(server);

io.on('connection', (socket) => {
    console.log('User connected:', socket.id);
    
    socket.on('join-room', (roomId) => {
        socket.join(roomId);
    });
    
    socket.on('send-message', (data) => {
        socket.to(data.room).emit('receive-message', data);
    });
    
    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
    });
});
```

```jsx
// Client-side (React)
import { io } from 'socket.io-client';

const Chat = () => {
    const [socket, setSocket] = useState(null);
    const [messages, setMessages] = useState([]);
    const [message, setMessage] = useState('');

    useEffect(() => {
        const newSocket = io('http://localhost:3001');
        setSocket(newSocket);
        
        newSocket.on('receive-message', (data) => {
            setMessages(prev => [...prev, data]);
        });

        return () => newSocket.close();
    }, []);

    const sendMessage = () => {
        if (socket && message) {
            socket.emit('send-message', { text: message, room: 'general' });
            setMessage('');
        }
    };

    return (
        <div>
            <div>
                {messages.map((msg, index) => (
                    <div key={index}>{msg.text}</div>
                ))}
            </div>
            <input
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
            />
            <button onClick={sendMessage}>Send</button>
        </div>
    );
};
```

---

## Common Interview Questions

### 1. What is the Virtual DOM?
**Answer**: Virtual DOM is a JavaScript representation of the real DOM. React creates a virtual copy of the DOM in memory, compares it with the previous version (diffing), and updates only the changed parts (reconciliation), making it more efficient than direct DOM manipulation.

### 2. Difference between SQL and NoSQL?
**Answer**: SQL databases are relational with structured schemas and ACID compliance (MySQL, PostgreSQL). NoSQL databases are non-relational, schema-flexible, and horizontally scalable (MongoDB, Cassandra). MongoDB stores data as documents instead of tables with rows.

### 3. What is Middleware in Express?
**Answer**: Middleware functions execute during the request-response cycle. They can modify request/response objects, end the cycle, or call the next middleware. Examples include authentication, logging, error handling, and parsing request bodies.

### 4. Explain React Hooks Rules
**Answer**: 
- Only call hooks at the top level of functions
- Don't call hooks inside loops, conditions, or nested functions
- Only call hooks from React functions or custom hooks
- This ensures consistent hook order between renders

### 5. What is CORS?
**Answer**: Cross-Origin Resource Sharing allows web pages to access resources from different domains. In Express, use cors middleware to enable cross-origin requests from your React frontend.

```javascript
const cors = require('cors');
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));
```

### 6. JWT vs Sessions - Which is better?
**Answer**: 
- **JWT**: Stateless, scalable, works across domains, but larger size and can't be revoked easily
- **Sessions**: Server-side storage, can be revoked instantly, smaller HTTP overhead, but requires server memory/database
- **Choice depends on**: Scalability needs, security requirements, and architecture

### 7. Explain Async/Await vs Promises
**Answer**: 
- **Promises**: Use `.then()` and `.catch()` chaining, can get complex with multiple operations
- **Async/Await**: Syntactic sugar over promises, makes asynchronous code look synchronous, easier error handling with try/catch
- Both handle asynchronous operations, async/await is generally more readable

### 8. What is useEffect dependency array?
**Answer**: 
- **Empty array []**: Effect runs once on mount
- **No array**: Effect runs on every render  
- **With dependencies [dep1, dep2]**: Effect runs when dependencies change
- **Cleanup function**: Return function from useEffect for cleanup

### 9. Explain MongoDB Indexing
**Answer**: Indexes improve query performance by creating shortcuts to data. Without indexes, MongoDB scans entire collections. Types include single field, compound, text, and geospatial indexes. Trade-off: faster reads vs slower writes and more storage.

### 10. What are Higher-Order Components (HOCs)?
**Answer**: Functions that take a component and return a new component with additional functionality. Used for cross-cutting concerns like authentication, logging, or data fetching. Modern alternative is custom hooks.

### 11. Explain Event Loop in Node.js
**Answer**: Single-threaded event loop handles I/O operations asynchronously. Phases include timers, pending callbacks, poll (fetching new I/O events), check (setImmediate), and close callbacks. Non-blocking I/O allows handling many concurrent connections.

### 12. What is prop drilling and how to solve it?
**Answer**: Passing props through multiple component levels unnecessarily. Solutions include:
- Context API for global state
- State management libraries (Redux, Zustand)
- Component composition
- Custom hooks

### 13. Difference between PUT and PATCH?
**Answer**: 
- **PUT**: Replaces entire resource (idempotent)
- **PATCH**: Partial update of resource
- **POST**: Creates new resource
- **DELETE**: Removes resource

### 14. Explain React reconciliation
**Answer**: Process of updating the DOM efficiently. React compares (diffs) current virtual DOM tree with previous version, identifies changes, and updates only modified elements. Uses keys to track list items and optimize re-renders.

### 15. What is connection pooling in MongoDB?
**Answer**: Maintains multiple database connections to handle concurrent requests efficiently. Mongoose creates a connection pool by default. Configure with options like `maxPoolSize`, `minPoolSize`, and connection timeouts.

### 16. How to handle errors in React?
**Answer**: 
- **Error Boundaries**: Catch JavaScript errors in component tree
- **Try/catch**: For async operations in useEffect
- **Global error handlers**: For unhandled promise rejections
- **Logging services**: Report errors to external services

### 17. Explain middleware execution order in Express
**Answer**: Middleware executes in the order it's defined using `app.use()`. Request flows through middleware stack, each calling `next()` to continue. Error middleware (4 parameters) handles errors and should be defined last.

### 18. What is React.memo and when to use it?
**Answer**: Higher-order component that memoizes functional components, preventing re-renders when props haven't changed. Use for expensive components that receive same props frequently. Similar to PureComponent for class components.

### 19. Explain aggregation in MongoDB
**Answer**: Pipeline-based data processing framework. Stages include `$match` (filter), `$group` (group by), `$sort`, `$project` (select fields), `$lookup` (join), and `$unwind` (flatten arrays). More powerful than simple find queries.

### 20. What is the difference between controlled and uncontrolled components?
**Answer**: 
- **Controlled**: React state controls input values via props and onChange
- **Uncontrolled**: DOM handles input state, accessed via refs
- Controlled components provide better data flow and validation

### 21. Explain hoisting in JavaScript
**Answer**: Variables and function declarations are moved to the top of their scope during compilation. `var` is hoisted and initialized with `undefined`, `let/const` are hoisted but not initialized (temporal dead zone), function declarations are fully hoisted.

### 22. What is the difference between `==` and `===`?
**Answer**: 
- **==** (loose equality): Performs type coercion before comparison
- **===** (strict equality): Compares both value and type without coercion
- Always prefer `===` for predictable comparisons

### 23. Explain JavaScript closures with example
**Answer**: Closure is when an inner function has access to outer function's variables even after outer function returns. Used for data privacy and creating factory functions.

```javascript
function counter() {
    let count = 0;
    return function() {
        return ++count;
    };
}
const increment = counter();
increment(); // 1
increment(); // 2
```

### 24. What is the difference between `null` and `undefined`?
**Answer**: 
- **undefined**: Variable declared but not assigned, or function doesn't return value
- **null**: Intentional absence of value, must be explicitly assigned
- Both are falsy values but different types

### 25. Explain React component lifecycle methods
**Answer**: 
- **Mounting**: constructor → render → componentDidMount
- **Updating**: render → componentDidUpdate
- **Unmounting**: componentWillUnmount
- **Functional components**: Use useEffect to replicate lifecycle behavior

### 26. What is Express.js and why use it?
**Answer**: Minimal web framework for Node.js that provides:
- Routing system
- Middleware support
- Template engine integration
- Simplified HTTP server creation
- Large ecosystem of plugins

### 27. Explain MongoDB schema design principles
**Answer**: 
- **Embed**: When data is accessed together (1:1, 1:few relationships)
- **Reference**: When data grows unbounded or accessed separately
- **Denormalize**: For read performance
- **Consider**: Query patterns, update frequency, data size

### 28. What is state management and why is it needed?
**Answer**: State management handles application data flow and storage. Needed because:
- Sharing state between components
- Avoiding prop drilling
- Predictable state updates
- Time-travel debugging
- Persistence across page refreshes

### 29. Difference between REST and GraphQL?
**Answer**: 
- **REST**: Multiple endpoints, over/under-fetching possible, caching easier
- **GraphQL**: Single endpoint, fetch exact data needed, more complex caching
- **Choice depends on**: Team expertise, caching needs, mobile optimization

### 30. Explain process.nextTick() vs setImmediate()
**Answer**: 
- **process.nextTick()**: Executes before any other I/O events in current phase
- **setImmediate()**: Executes in check phase of event loop
- nextTick has higher priority and can starve I/O if overused

### 31. What is React key prop and why is it important?
**Answer**: Keys help React identify which list items have changed, added, or removed. Important for:
- Performance optimization during re-renders
- Preserving component state
- Avoiding rendering bugs
- Should be stable, unique, and predictable

### 32. Explain MongoDB transactions
**Answer**: ACID operations across multiple documents/collections. Required for operations where data consistency is critical. Use sessions to group operations and either commit all or rollback on failure.

### 33. What is the purpose of package.json?
**Answer**: Metadata file for Node.js projects containing:
- Project information (name, version, description)
- Dependencies and devDependencies
- Scripts for automation
- Engine requirements
- Repository and license info

### 34. Difference between npm and npx?
**Answer**: 
- **npm**: Package manager for installing/managing packages
- **npx**: Package runner that executes packages without installing globally
- npx is useful for running one-time commands and keeping global namespace clean

### 35. What is React StrictMode?
**Answer**: Development tool that:
- Detects unsafe lifecycles
- Warns about deprecated APIs
- Detects side effects during rendering
- Helps with concurrent features preparation
- Only runs in development mode

### 36. Explain database normalization vs denormalization
**Answer**: 
- **Normalization**: Organizing data to reduce redundancy and dependency
- **Denormalization**: Adding redundancy for performance optimization
- **In MongoDB**: Often denormalize for read performance due to document model

### 37. What is the difference between HTTP and HTTPS?
**Answer**: 
- **HTTP**: Unencrypted data transfer on port 80
- **HTTPS**: Encrypted using SSL/TLS on port 443
- HTTPS provides data integrity, authentication, and encryption

### 38. Explain React Fiber
**Answer**: React's reconciliation engine that:
- Enables incremental rendering
- Allows pausing and resuming work
- Prioritizes updates based on importance
- Improves performance for complex UIs
- Foundation for React 18 concurrent features

### 39. What is the purpose of MongoDB ObjectId?
**Answer**: 12-byte unique identifier containing:
- 4-byte timestamp
- 5-byte random value unique to machine/process
- 3-byte incrementing counter
- Provides ordering and uniqueness without central coordination

### 40. How to optimize React application performance?
**Answer**: 
- Use React.memo for component memoization
- Implement useMemo and useCallback for expensive calculations
- Code splitting with React.lazy
- Avoid inline functions in render
- Use production builds
- Optimize bundle size
- Implement virtual scrolling for large lists
