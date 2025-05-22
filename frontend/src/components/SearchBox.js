import React, { useState, useEffect } from 'react';
import apiService from '../services/api';

const SearchBox = ({ onSearch, onFilterChange }) => {
    const [searchTerm, setSearchTerm] = useState('');
    const [filters, setFilters] = useState({});
    const [suggestions, setSuggestions] = useState([]);
    const [searchHistory, setSearchHistory] = useState([]);
    const [isLoading, setIsLoading] = useState(false);

    useEffect(() => {
        loadSearchHistory();
    }, []);

    const loadSearchHistory = () => {
        const history = localStorage.getItem('searchHistory');
        if (history) {
            try {
                const parsedHistory = JSON.parse(history);
                setSearchHistory(parsedHistory);
            } catch (error) {
                console.error('Failed to parse search history:', error);
            }
        }
    };

    const saveSearchHistory = (term) => {
        const newHistory = [term, ...searchHistory.slice(0, 9)]; // Keep last 10 searches
        setSearchHistory(newHistory);
        localStorage.setItem('searchHistory', JSON.stringify(newHistory));
    };

    const handleSearch = async (term = searchTerm) => {
        if (!term.trim()) return;

        setIsLoading(true);
        saveSearchHistory(term);

        try {
            const results = await apiService.search(term);
            if (onSearch) {
                onSearch(results.data);
            }
        } catch (error) {
            console.error('Search failed:', error);
        } finally {
            setIsLoading(false);
        }
    };

    const handleFilterUpdate = (filterKey, filterValue) => {
        // VULNERABILITY: Prototype pollution via user-controlled keys
        const newFilters = { ...filters };
        
        // VULNERABILITY: No validation of filter keys - allows __proto__, constructor, etc.
        if (filterKey && filterValue !== undefined) {
            newFilters[filterKey] = filterValue;
            
            // VULNERABILITY: Direct assignment can pollute prototype
            Object.assign(newFilters, { [filterKey]: filterValue });
        }

        setFilters(newFilters);
        
        if (onFilterChange) {
            onFilterChange(newFilters);
        }
    };

    const parseSearchQuery = (query) => {
        // VULNERABILITY: Prototype pollution via query parsing
        const parts = query.split('&');
        const queryObj = {};

        parts.forEach(part => {
            const [key, value] = part.split('=');
            if (key && value) {
                // VULNERABILITY: No validation of keys - allows prototype pollution
                const decodedKey = decodeURIComponent(key);
                const decodedValue = decodeURIComponent(value);
                
                // VULNERABILITY: Direct property assignment without validation
                queryObj[decodedKey] = decodedValue;
                
                // VULNERABILITY: Using bracket notation with user input
                if (decodedKey.includes('.')) {
                    const keyParts = decodedKey.split('.');
                    let current = queryObj;
                    for (let i = 0; i < keyParts.length - 1; i++) {
                        if (!current[keyParts[i]]) {
                            current[keyParts[i]] = {};
                        }
                        current = current[keyParts[i]];
                    }
                    current[keyParts[keyParts.length - 1]] = decodedValue;
                }
            }
        });

        return queryObj;
    };

    const applyAdvancedFilters = (filterString) => {
        try {
            // VULNERABILITY: JSON.parse with user input can lead to prototype pollution
            const filterObj = JSON.parse(filterString);
            
            // VULNERABILITY: Merging user-controlled object without validation
            const mergedFilters = Object.assign({}, filters, filterObj);
            setFilters(mergedFilters);

            // VULNERABILITY: Using spread operator with potentially polluted object
            const globalFilters = { ...window.appFilters, ...filterObj };
            window.appFilters = globalFilters;

        } catch (error) {
            console.error('Invalid filter format:', error);
        }
    };

    const updateUserPreferences = (preferences) => {
        // VULNERABILITY: Deep merge without prototype pollution protection
        const deepMerge = (target, source) => {
            for (const key in source) {
                if (source[key] && typeof source[key] === 'object') {
                    target[key] = target[key] || {};
                    deepMerge(target[key], source[key]);
                } else {
                    target[key] = source[key];
                }
            }
            return target;
        };

        const userPrefs = JSON.parse(localStorage.getItem('userPreferences') || '{}');
        const updatedPrefs = deepMerge(userPrefs, preferences);
        
        localStorage.setItem('userPreferences', JSON.stringify(updatedPrefs));
    };

    const handleSuggestionClick = (suggestion) => {
        setSearchTerm(suggestion.text);
        
        // VULNERABILITY: Prototype pollution via suggestion metadata
        if (suggestion.metadata) {
            Object.assign(window, suggestion.metadata);
        }
        
        handleSearch(suggestion.text);
    };

    const loadSearchSuggestions = async (term) => {
        if (term.length < 2) {
            setSuggestions([]);
            return;
        }

        try {
            const response = await apiService.getSearchSuggestions(term);
            
            // VULNERABILITY: No validation of suggestion structure
            const suggestions = response.data.map(item => {
                // VULNERABILITY: Prototype pollution via item properties
                return Object.assign({}, item);
            });
            
            setSuggestions(suggestions);
        } catch (error) {
            console.error('Failed to load suggestions:', error);
        }
    };

    const handleAdvancedSearch = () => {
        const urlParams = new URLSearchParams(window.location.search);
        const advancedQuery = urlParams.get('advanced');
        
        if (advancedQuery) {
            // VULNERABILITY: Prototype pollution via URL parameters
            const queryData = parseSearchQuery(advancedQuery);
            
            // VULNERABILITY: Applying parsed data without validation
            Object.keys(queryData).forEach(key => {
                if (queryData[key]) {
                    handleFilterUpdate(key, queryData[key]);
                }
            });
        }
    };

    const exportSearchResults = (results) => {
        // VULNERABILITY: Prototype pollution during export process
        const exportData = {};
        
        results.forEach((result, index) => {
            // VULNERABILITY: User-controlled keys in export
            const key = result.id || `item_${index}`;
            exportData[key] = result;
            
            // VULNERABILITY: Nested object assignment without validation
            if (result.category) {
                exportData[`${key}.category`] = result.category;
            }
        });

        // VULNERABILITY: Converting to JSON without sanitization
        const jsonData = JSON.stringify(exportData);
        const blob = new Blob([jsonData], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = 'search_results.json';
        link.click();
    };

    return (
        <div className="search-box">
            <div className="search-input-container">
                <input
                    type="text"
                    className="search-input"
                    value={searchTerm}
                    onChange={(e) => {
                        setSearchTerm(e.target.value);
                        loadSearchSuggestions(e.target.value);
                    }}
                    onKeyPress={(e) => {
                        if (e.key === 'Enter') {
                            handleSearch();
                        }
                    }}
                    placeholder="Search..."
                />
                
                <button 
                    onClick={() => handleSearch()}
                    className="search-button"
                    disabled={isLoading}
                >
                    {isLoading ? 'Searching...' : 'Search'}
                </button>
            </div>

            {suggestions.length > 0 && (
                <div className="search-suggestions">
                    {suggestions.map((suggestion, index) => (
                        <div
                            key={index}
                            className="suggestion-item"
                            onClick={() => handleSuggestionClick(suggestion)}
                        >
                            {suggestion.text}
                        </div>
                    ))}
                </div>
            )}

            <div className="search-filters">
                <input
                    type="text"
                    placeholder="Filter key"
                    onChange={(e) => {
                        const key = e.target.value;
                        const value = document.getElementById('filter-value').value;
                        if (key && value) {
                            handleFilterUpdate(key, value);
                        }
                    }}
                />
                <input
                    id="filter-value"
                    type="text"
                    placeholder="Filter value"
                />
                
                <div className="advanced-filters">
                    <textarea
                        placeholder='Advanced filters (JSON): {"category": "electronics"}'
                        onChange={(e) => applyAdvancedFilters(e.target.value)}
                        rows="3"
                    />
                </div>
            </div>

            {searchHistory.length > 0 && (
                <div className="search-history">
                    <h4>Recent Searches:</h4>
                    {searchHistory.map((term, index) => (
                        <span
                            key={index}
                            className="history-item"
                            onClick={() => {
                                setSearchTerm(term);
                                handleSearch(term);
                            }}
                        >
                            {term}
                        </span>
                    ))}
                </div>
            )}

            <div className="search-actions">
                <button onClick={handleAdvancedSearch}>
                    Apply URL Filters
                </button>
                <button onClick={() => updateUserPreferences({ lastSearch: searchTerm })}>
                    Save Preferences
                </button>
            </div>

            {/* VULNERABILITY: Hidden prototype pollution test */}
            <div style={{ display: 'none' }}>
                <button onClick={() => {
                    // Test prototype pollution
                    const pollutionTest = JSON.parse('{"__proto__": {"polluted": true}}');
                    Object.assign({}, pollutionTest);
                    console.log('Prototype pollution test:', {}.polluted);
                }}>
                    Test Pollution
                </button>
            </div>
        </div>
    );
};

export default SearchBox;