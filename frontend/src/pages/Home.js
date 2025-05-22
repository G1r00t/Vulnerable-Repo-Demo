/**
 * Home Page Component
 * This is a clean, well-written component with no security vulnerabilities
 * Demonstrates proper React/JavaScript practices
 */

import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { createSafeElement } from '../utils/helpers';

const HomePage = () => {
    const [featuredProducts, setFeaturedProducts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        fetchFeaturedProducts();
    }, []);

    // Clean async function with proper error handling
    const fetchFeaturedProducts = async () => {
        try {
            setLoading(true);
            const response = await fetch('/api/products/featured', {
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            
            // Input validation
            if (Array.isArray(data) && data.length <= 50) {
                setFeaturedProducts(data);
            } else {
                throw new Error('Invalid product data received');
            }
        } catch (err) {
            console.error('Error fetching featured products:', err);
            setError('Failed to load featured products. Please try again later.');
        } finally {
            setLoading(false);
        }
    };

    // Clean event handler
    const handleNewsletterSignup = async (event) => {
        event.preventDefault();
        
        const formData = new FormData(event.target);
        const email = formData.get('email');

        // Input validation
        if (!email || !isValidEmail(email)) {
            alert('Please enter a valid email address.');
            return;
        }

        try {
            const response = await fetch('/api/newsletter/subscribe', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email })
            });

            if (response.ok) {
                alert('Thank you for subscribing to our newsletter!');
                event.target.reset();
            } else {
                throw new Error('Subscription failed');
            }
        } catch (err) {
            console.error('Newsletter signup error:', err);
            alert('Failed to subscribe. Please try again later.');
        }
    };

    // Clean utility function
    const isValidEmail = (email) => {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    };

    // Clean formatting function
    const formatPrice = (price) => {
        return new Intl.NumberFormat('en-US', {
            style: 'currency',
            currency: 'USD'
        }).format(price);
    };

    // Clean render methods
    const renderHeroSection = () => (
        <section className="hero-section">
            <div className="hero-content">
                <h1>Welcome to SecureShop</h1>
                <p>Your trusted destination for quality products and secure shopping.</p>
                <Link to="/products" className="cta-button">
                    Shop Now
                </Link>
            </div>
        </section>
    );

    const renderFeaturedProducts = () => {
        if (loading) {
            return <div className="loading">Loading products...</div>;
        }

        if (error) {
            return <div className="error">{error}</div>;
        }

        return (
            <section className="featured-products">
                <h2>Featured Products</h2>
                <div className="product-grid">
                    {featuredProducts.map(product => (
                        <div key={product.id} className="product-card">
                            <img 
                                src={product.imageUrl} 
                                alt={product.name}
                                onError={(e) => {
                                    e.target.src = '/images/placeholder-product.jpg';
                                }}
                            />
                            <div className="product-info">
                                <h3>{product.name}</h3>
                                <p className="product-description">
                                    {product.description}
                                </p>
                                <p className="product-price">
                                    {formatPrice(product.price)}
                                </p>
                                <Link 
                                    to={`/products/${product.id}`}
                                    className="product-link"
                                >
                                    View Details
                                </Link>
                            </div>
                        </div>
                    ))}
                </div>
            </section>
        );
    };

    const renderNewsletterSection = () => (
        <section className="newsletter-section">
            <div className="newsletter-content">
                <h2>Stay Updated</h2>
                <p>Subscribe to our newsletter for the latest deals and updates.</p>
                <form onSubmit={handleNewsletterSignup} className="newsletter-form">
                    <input
                        type="email"
                        name="email"
                        placeholder="Enter your email address"
                        required
                        className="email-input"
                    />
                    <button type="submit" className="subscribe-button">
                        Subscribe
                    </button>
                </form>
            </div>
        </section>
    );

    const renderFooterLinks = () => (
        <section className="footer-links">
            <div className="link-group">
                <h3>Quick Links</h3>
                <ul>
                    <li><Link to="/about">About Us</Link></li>
                    <li><Link to="/contact">Contact</Link></li>
                    <li><Link to="/support">Customer Support</Link></li>
                    <li><Link to="/privacy">Privacy Policy</Link></li>
                    <li><Link to="/terms">Terms of Service</Link></li>
                </ul>
            </div>
        </section>
    );

    return (
        <div className="home-page">
            {renderHeroSection()}
            {renderFeaturedProducts()}
            {renderNewsletterSection()}
            {renderFooterLinks()}
        </div>
    );
};

export default HomePage;