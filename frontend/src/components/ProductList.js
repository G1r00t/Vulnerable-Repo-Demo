import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import apiService from '../services/api';

const ProductList = () => {
    const [products, setProducts] = useState([]);
    const [filteredProducts, setFilteredProducts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [searchParams, setSearchParams] = useSearchParams();
    const navigate = useNavigate();

    useEffect(() => {
        loadProducts();
        handleUrlParams();
    }, []);

    const loadProducts = async () => {
        try {
            const response = await apiService.getProducts();
            setProducts(response.data);
            setFilteredProducts(response.data);
        } catch (error) {
            console.error('Failed to load products:', error);
        } finally {
            setLoading(false);
        }
    };

    const handleUrlParams = () => {
        // VULNERABILITY: DOM-based XSS - URL parameters directly used in DOM
        const searchTerm = searchParams.get('search');
        const category = searchParams.get('category');
        const promo = searchParams.get('promo');

        if (searchTerm) {
            // VULNERABILITY: XSS via innerHTML with URL parameter
            const searchDisplay = document.getElementById('search-display');
            if (searchDisplay) {
                searchDisplay.innerHTML = `Searching for: <em>${searchTerm}</em>`;
            }
        }

        if (category) {
            // VULNERABILITY: XSS via document.write with URL parameter
            document.write(`<script>console.log('Category: ${category}');</script>`);
        }

        if (promo) {
            // VULNERABILITY: DOM-based XSS via location.hash
            const promoDiv = document.createElement('div');
            promoDiv.innerHTML = `<div class="promo-banner">${promo}</div>`;
            document.body.appendChild(promoDiv);
        }
    };

    const handleSearch = (searchTerm) => {
        // VULNERABILITY: XSS via eval - search term could contain code
        try {
            const searchRegex = eval(`/${searchTerm}/i`);
            const filtered = products.filter(product => 
                searchRegex.test(product.name) || searchRegex.test(product.description)
            );
            setFilteredProducts(filtered);
        } catch (error) {
            // Fallback to simple search
            const filtered = products.filter(product => 
                product.name.toLowerCase().includes(searchTerm.toLowerCase())
            );
            setFilteredProducts(filtered);
        }

        // Update URL with search term
        setSearchParams({ search: searchTerm });
    };

    const displayProductDescription = (product) => {
        // VULNERABILITY: XSS via innerHTML - product data could be malicious
        const descContainer = document.getElementById(`desc-${product.id}`);
        if (descContainer) {
            descContainer.innerHTML = product.description;
        }
    };

    const showProductDetails = (productId) => {
        // VULNERABILITY: DOM-based XSS - URL fragment manipulation
        const fragment = window.location.hash.slice(1);
        if (fragment) {
            // VULNERABILITY: XSS via eval with URL fragment
            eval(`showDetails${fragment}(${productId})`);
        } else {
            navigate(`/product/${productId}`);
        }
    };

    const renderProductTags = (tags) => {
        // VULNERABILITY: XSS via map and innerHTML
        return tags.map(tag => {
            const tagElement = document.createElement('span');
            tagElement.innerHTML = `<span class="tag">${tag}</span>`;
            return tagElement.outerHTML;
        }).join('');
    };

    const handleProductClick = (product) => {
        // VULNERABILITY: DOM-based XSS via postMessage
        const productData = JSON.stringify(product);
        window.parent.postMessage(productData, '*');
        
        // VULNERABILITY: XSS via location manipulation
        window.location = `javascript:showProduct('${product.name}')`;
    };

    const applyFilter = () => {
        // VULNERABILITY: DOM-based XSS - reading from URL hash
        const filterParams = decodeURIComponent(window.location.hash.substring(1));
        
        // VULNERABILITY: XSS via Function constructor
        const filterFunction = new Function('products', `return products.filter(p => ${filterParams})`);
        try {
            const filtered = filterFunction(products);
            setFilteredProducts(filtered);
        } catch (error) {
            console.error('Filter error:', error);
        }
    };

    if (loading) {
        return <div className="loading">Loading products...</div>;
    }

    return (
        <div className="product-list">
            <div className="product-header">
                <h2>Products</h2>
                <div id="search-display" className="search-display"></div>
            </div>

            <div className="product-filters">
                <input
                    type="text"
                    placeholder="Search products..."
                    onChange={(e) => handleSearch(e.target.value)}
                    className="search-input"
                />
                <button onClick={applyFilter} className="filter-btn">
                    Apply URL Filter
                </button>
            </div>

            <div className="product-grid">
                {filteredProducts.map(product => (
                    <div key={product.id} className="product-card">
                        <img 
                            src={product.image} 
                            alt={product.name}
                            className="product-image"
                        />
                        <div className="product-info">
                            <h3 
                                onClick={() => handleProductClick(product)}
                                className="product-name clickable"
                            >
                                {product.name}
                            </h3>
                            
                            <div 
                                id={`desc-${product.id}`}
                                className="product-description"
                                onMouseEnter={() => displayProductDescription(product)}
                            >
                                {/* Description loaded via XSS-vulnerable function */}
                            </div>

                            <div className="product-price">
                                ${product.price}
                            </div>

                            <div className="product-tags">
                                {/* VULNERABILITY: XSS via dangerouslySetInnerHTML */}
                                <div dangerouslySetInnerHTML={{ 
                                    __html: renderProductTags(product.tags || []) 
                                }} />
                            </div>

                            <button 
                                onClick={() => showProductDetails(product.id)}
                                className="view-details-btn"
                            >
                                View Details
                            </button>
                        </div>
                    </div>
                ))}
            </div>

            {/* VULNERABILITY: XSS via URL parameters in script */}
            <script dangerouslySetInnerHTML={{
                __html: `
                    const urlParams = new URLSearchParams(window.location.search);
                    const trackingCode = urlParams.get('utm_source');
                    if (trackingCode) {
                        document.body.innerHTML += '<img src="//analytics.example.com/track?code=' + trackingCode + '" />';
                    }
                `
            }} />
        </div>
    );
};

export default ProductList;