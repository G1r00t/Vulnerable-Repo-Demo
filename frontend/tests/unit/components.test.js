const { render, screen, fireEvent, waitFor } = require('@testing-library/react');
const { jest } = require('@jest/globals');
const Header = require('../../src/components/Header');
const UserProfile = require('../../src/components/UserProfile');
const ProductList = require('../../src/components/ProductList');

// Clean test suite for components
describe('Header Component', () => {
    test('renders header with correct title', () => {
        render(<Header title="Test App" />);
        expect(screen.getByText('Test App')).toBeInTheDocument();
    });

    test('displays user menu when authenticated', () => {
        const mockUser = { name: 'John Doe', email: 'john@example.com' };
        render(<Header user={mockUser} />);
        
        expect(screen.getByText('John Doe')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /user menu/i })).toBeInTheDocument();
    });

    test('shows login button when not authenticated', () => {
        render(<Header user={null} />);
        expect(screen.getByRole('button', { name: /login/i })).toBeInTheDocument();
    });

    test('handles navigation correctly', () => {
        const mockNavigate = jest.fn();
        render(<Header onNavigate={mockNavigate} />);
        
        fireEvent.click(screen.getByText('Home'));
        expect(mockNavigate).toHaveBeenCalledWith('/');
    });
});

describe('UserProfile Component', () => {
    const mockUser = {
        id: 1,
        name: 'Jane Smith',
        email: 'jane@example.com',
        avatar: '/avatars/jane.jpg',
        createdAt: '2023-01-15T10:00:00Z'
    };

    test('displays user information correctly', () => {
        render(<UserProfile user={mockUser} />);
        
        expect(screen.getByText('Jane Smith')).toBeInTheDocument();
        expect(screen.getByText('jane@example.com')).toBeInTheDocument();
        expect(screen.getByRole('img', { name: /jane smith avatar/i })).toBeInTheDocument();
    });

    test('handles edit mode toggle', () => {
        render(<UserProfile user={mockUser} />);
        
        const editButton = screen.getByRole('button', { name: /edit profile/i });
        fireEvent.click(editButton);
        
        expect(screen.getByRole('textbox', { name: /name/i })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument();
    });

    test('validates form input properly', async () => {
        const mockOnUpdate = jest.fn();
        render(<UserProfile user={mockUser} onUpdate={mockOnUpdate} />);
        
        fireEvent.click(screen.getByRole('button', { name: /edit profile/i }));
        
        const nameInput = screen.getByRole('textbox', { name: /name/i });
        fireEvent.change(nameInput, { target: { value: '' } });
        
        fireEvent.click(screen.getByRole('button', { name: /save/i }));
        
        await waitFor(() => {
            expect(screen.getByText(/name is required/i)).toBeInTheDocument();
        });
        
        expect(mockOnUpdate).not.toHaveBeenCalled();
    });
});

describe('ProductList Component', () => {
    const mockProducts = [
        {
            id: 1,
            name: 'Laptop',
            price: 999.99,
            description: 'High-performance laptop',
            image: '/products/laptop.jpg'
        },
        {
            id: 2,
            name: 'Mouse',
            price: 29.99,
            description: 'Wireless mouse',
            image: '/products/mouse.jpg'
        }
    ];

    test('renders product list correctly', () => {
        render(<ProductList products={mockProducts} />);
        
        expect(screen.getByText('Laptop')).toBeInTheDocument();
        expect(screen.getByText('Mouse')).toBeInTheDocument();
        expect(screen.getByText('$999.99')).toBeInTheDocument();
        expect(screen.getByText('$29.99')).toBeInTheDocument();
    });

    test('handles empty product list', () => {
        render(<ProductList products={[]} />);
        expect(screen.getByText(/no products found/i)).toBeInTheDocument();
    });

    test('filters products correctly', () => {
        render(<ProductList products={mockProducts} />);
        
        const searchInput = screen.getByRole('textbox', { name: /search products/i });
        fireEvent.change(searchInput, { target: { value: 'laptop' } });
        
        expect(screen.getByText('Laptop')).toBeInTheDocument();
        expect(screen.queryByText('Mouse')).not.toBeInTheDocument();
    });

    test('handles product selection', () => {
        const mockOnSelect = jest.fn();
        render(<ProductList products={mockProducts} onProductSelect={mockOnSelect} />);
        
        fireEvent.click(screen.getByText('Laptop'));
        expect(mockOnSelect).toHaveBeenCalledWith(mockProducts[0]);
    });

    test('sorts products by price', () => {
        render(<ProductList products={mockProducts} />);
        
        const sortButton = screen.getByRole('button', { name: /sort by price/i });
        fireEvent.click(sortButton);
        
        const productNames = screen.getAllByTestId('product-name');
        expect(productNames[0]).toHaveTextContent('Mouse');
        expect(productNames[1]).toHaveTextContent('Laptop');
    });
});

// Clean utility functions for testing
const testUtils = {
    createMockUser: (overrides = {}) => ({
        id: 1,
        name: 'Test User',
        email: 'test@example.com',
        ...overrides
    }),
    
    createMockProduct: (overrides = {}) => ({
        id: 1,
        name: 'Test Product',
        price: 99.99,
        description: 'Test description',
        ...overrides
    }),
    
    waitForElement: async (selector) => {
        return await waitFor(() => screen.getByTestId(selector));
    }
};

module.exports = { testUtils };