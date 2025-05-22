/**
 * Profile Page Component
 * Contains CSRF vulnerabilities and related security issues
 */

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const ProfilePage = () => {
    const [user, setUser] = useState(null);
    const [editMode, setEditMode] = useState(false);
    const [formData, setFormData] = useState({});
    const [avatar, setAvatar] = useState(null);
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();

    useEffect(() => {
        loadUserProfile();
    }, []);

    const loadUserProfile = async () => {
        try {
            const token = localStorage.getItem('authToken');
            if (!token) {
                navigate('/login');
                return;
            }

            const response = await fetch('/api/user/profile', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (response.ok) {
                const userData = await response.json();
                setUser(userData);
                setFormData(userData);
            }
        } catch (error) {
            console.error('Error loading profile:', error);
        } finally {
            setLoading(false);
        }
    };

    // VULNERABILITY: Form submission without CSRF token
    const handleProfileUpdate = async (event) => {
        event.preventDefault();

        try {
            const token = localStorage.getItem('authToken');
            
            // VULNERABILITY: No CSRF protection - vulnerable to CSRF attacks
            const response = await fetch('/api/user/profile', {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                    // Missing CSRF token header
                },
                body: JSON.stringify(formData)
            });

            if (response.ok) {
                const updatedUser = await response.json();
                setUser(updatedUser);
                setEditMode(false);
                alert('Profile updated successfully!');
            } else {
                alert('Failed to update profile');
            }
        } catch (error) {
            console.error('Profile update error:', error);
            alert('Error updating profile');
        }
    };

    // VULNERABILITY: Password change without CSRF protection
    const handlePasswordChange = async (event) => {
        event.preventDefault();
        
        const currentPassword = event.target.currentPassword.value;
        const newPassword = event.target.newPassword.value;
        const confirmPassword = event.target.confirmPassword.value;

        if (newPassword !== confirmPassword) {
            alert('New passwords do not match');
            return;
        }

        try {
            const token = localStorage.getItem('authToken');
            
            // VULNERABILITY: Critical action without CSRF token
            const response = await fetch('/api/user/change-password', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                    // Missing X-CSRF-Token header
                },
                body: JSON.stringify({
                    currentPassword,
                    newPassword
                })
            });

            if (response.ok) {
                alert('Password changed successfully!');
                event.target.reset();
            } else {
                const error = await response.json();
                alert(`Password change failed: ${error.message}`);
            }
        } catch (error) {
            console.error('Password change error:', error);
            alert('Error changing password');
        }
    };

    // VULNERABILITY: Account deletion without proper CSRF protection
    const handleAccountDeletion = async () => {
        const confirmation = window.confirm(
            'Are you sure you want to delete your account? This action cannot be undone.'
        );

        if (!confirmation) return;

        // VULNERABILITY: Second confirmation can be bypassed by automated attacks
        const finalConfirmation = window.prompt(
            'Type "DELETE" to confirm account deletion:'
        );

        if (finalConfirmation !== 'DELETE') {
            alert('Account deletion cancelled');
            return;
        }

        try {
            const token = localStorage.getItem('authToken');
            
            // VULNERABILITY: Critical destructive action without CSRF token
            const response = await fetch('/api/user/delete-account', {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
                // Missing CSRF protection for account deletion
            });

            if (response.ok) {
                alert('Account deleted successfully');
                localStorage.clear();
                navigate('/');
            } else {
                alert('Failed to delete account');
            }
        } catch (error) {
            console.error('Account deletion error:', error);
            alert('Error deleting account');
        }
    };

    // VULNERABILITY: Email change without proper verification
    const handleEmailChange = async (newEmail) => {
        try {
            const token = localStorage.getItem('authToken');
            
            // VULNERABILITY: Email change without CSRF token or current password
            const response = await fetch('/api/user/change-email', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ newEmail })
            });

            if (response.ok) {
                alert('Email change request sent! Check your new email for confirmation.');
                // VULNERABILITY: Optimistic UI update before email verification
                setUser(prev => ({ ...prev, email: newEmail }));
                setFormData(prev => ({ ...prev, email: newEmail }));
            }
        } catch (error) {
            console.error('Email change error:', error);
        }
    };

    // VULNERABILITY: Avatar upload without CSRF protection
    const handleAvatarUpload = async (event) => {
        const file = event.target.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append('avatar', file);

        try {
            const token = localStorage.getItem('authToken');
            
            // VULNERABILITY: File upload without CSRF token
            const response = await fetch('/api/user/avatar', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                    // Missing CSRF token for file upload
                },
                body: formData
            });

            if (response.ok) {
                const result = await response.json();
                setUser(prev => ({ ...prev, avatar: result.avatarUrl }));
                alert('Avatar updated successfully!');
            }
        } catch (error) {
            console.error('Avatar upload error:', error);
        }
    };

    // VULNERABILITY: Privacy settings change without CSRF protection
    const handlePrivacySettingsChange = async (settings) => {
        try {
            const token = localStorage.getItem('authToken');
            
            // VULNERABILITY: Privacy settings update without CSRF token
            const response = await fetch('/api/user/privacy-settings', {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(settings)
            });

            if (response.ok) {
                alert('Privacy settings updated');
            }
        } catch (error) {
            console.error('Privacy settings error:', error);
        }
    };

    // VULNERABILITY: Newsletter subscription change via GET request
    const handleNewsletterToggle = async (subscribe) => {
        try {
            // VULNERABILITY: State-changing operation via GET request
            const response = await fetch(`/api/user/newsletter?action=${subscribe ? 'subscribe' : 'unsubscribe'}&user=${user.id}`, {
                method: 'GET'
            });

            if (response.ok) {
                setUser(prev => ({ ...prev, newsletterSubscribed: subscribe }));
            }
        } catch (error) {
            console.error('Newsletter toggle error:', error);
        }
    };

    // VULNERABILITY: Social media account linking without CSRF protection
    const handleSocialAccountLink = async (provider, action) => {
        try {
            const token = localStorage.getItem('authToken');
            
            // VULNERABILITY: Account linking without CSRF protection
            const response = await fetch(`/api/user/social-accounts/${provider}`, {
                method: action === 'link' ? 'POST' : 'DELETE',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                alert(`${provider} account ${action}ed successfully`);
                loadUserProfile(); // Reload to get updated social accounts
            }
        } catch (error) {
            console.error('Social account error:', error);
        }
    };

    // VULNERABILITY: Two-factor authentication toggle without proper verification
    const handleTwoFactorToggle = async (enable) => {
        try {
            const token = localStorage.getItem('authToken');
            
            // VULNERABILITY: Critical security setting change without CSRF token
            const response = await fetch('/api/user/two-factor', {
                method: enable ? 'POST' : 'DELETE',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
                // Missing CSRF token for security-critical operation
            });

            if (response.ok) {
                const result = await response.json();
                setUser(prev => ({ ...prev, twoFactorEnabled: enable }));
                
                if (enable && result.qrCode) {
                    // VULNERABILITY: QR code displayed without additional verification
                    alert(`Two-factor authentication enabled! QR Code: ${result.qrCode}`);
                }
            }
        } catch (error) {
            console.error('Two-factor toggle error:', error);
        }
    };

    const handleInputChange = (event) => {
        const { name, value } = event.target;
        setFormData(prev => ({
            ...prev,
            [name]: value
        }));
    };

    if (loading) {
        return <div className="loading">Loading profile...</div>;
    }

    return (
        <div className="profile-page">
            <div className="profile-container">
                <h1>My Profile</h1>

                {/* Profile Information Section */}
                <section className="profile-info">
                    <div className="avatar-section">
                        <img 
                            src={user?.avatar || '/images/default-avatar.png'} 
                            alt="User Avatar"
                            className="user-avatar"
                        />
                        <div>
                            <label htmlFor="avatar-upload" className="avatar-upload-label">
                                Change Avatar
                            </label>
                            <input
                                id="avatar-upload"
                                type="file"
                                accept="image/*"
                                onChange={handleAvatarUpload}
                                style={{ display: 'none' }}
                            />
                        </div>
                    </div>

                    {editMode ? (
                        <form onSubmit={handleProfileUpdate} className="profile-form">
                            <div className="form-group">
                                <label>Full Name:</label>
                                <input
                                    type="text"
                                    name="name"
                                    value={formData.name || ''}
                                    onChange={handleInputChange}
                                    required
                                />
                            </div>

                            <div className="form-group">
                                <label>Email:</label>
                                <input
                                    type="email"
                                    name="email"
                                    value={formData.email || ''}
                                    onChange={handleInputChange}
                                    required
                                />
                            </div>

                            <div className="form-group">
                                <label>Phone:</label>
                                <input
                                    type="tel"
                                    name="phone"
                                    value={formData.phone || ''}
                                    onChange={handleInputChange}
                                />
                            </div>

                            <div className="form-group">
                                <label>Bio:</label>
                                <textarea
                                    name="bio"
                                    value={formData.bio || ''}
                                    onChange={handleInputChange}
                                    rows="4"
                                />
                            </div>

                            <div className="form-actions">
                                <button type="submit">Save Changes</button>
                                <button 
                                    type="button" 
                                    onClick={() => setEditMode(false)}
                                >
                                    Cancel
                                </button>
                            </div>
                        </form>
                    ) : (
                        <div className="profile-display">
                            <p><strong>Name:</strong> {user?.name}</p>
                            <p><strong>Email:</strong> {user?.email}</p>
                            <p><strong>Phone:</strong> {user?.phone || 'Not provided'}</p>
                            <p><strong>Bio:</strong> {user?.bio || 'No bio provided'}</p>
                            <button onClick={() => setEditMode(true)}>Edit Profile</button>
                        </div>
                    )}
                </section>

                {/* Password Change Section */}
                <section className="password-section">
                    <h2>Change Password</h2>
                    <form onSubmit={handlePasswordChange}>
                        <div className="form-group">
                            <label>Current Password:</label>
                            <input type="password" name="currentPassword" required />
                        </div>
                        <div className="form-group">
                            <label>New Password:</label>
                            <input type="password" name="newPassword" required />
                        </div>
                        <div className="form-group">
                            <label>Confirm New Password:</label>
                            <input type="password" name="confirmPassword" required />
                        </div>
                        <button type="submit">Change Password</button>
                    </form>
                </section>

                {/* Privacy Settings Section */}
                <section className="privacy-section">
                    <h2>Privacy Settings</h2>
                    <div className="privacy-options">
                        <label>
                            <input
                                type="checkbox"
                                defaultChecked={user?.profilePublic}
                                onChange={(e) => 
                                    handlePrivacySettingsChange({ profilePublic: e.target.checked })
                                }
                            />
                            Make profile public
                        </label>
                        
                        <label>
                            <input
                                type="checkbox"
                                defaultChecked={user?.showEmail}
                                onChange={(e) => 
                                    handlePrivacySettingsChange({ showEmail: e.target.checked })
                                }
                            />
                            Show email on profile
                        </label>

                        <label>
                            <input
                                type="checkbox"
                                checked={user?.newsletterSubscribed}
                                onChange={(e) => handleNewsletterToggle(e.target.checked)}
                            />
                            Subscribe to newsletter
                        </label>
                    </div>
                </section>

                {/* Security Settings Section */}
                <section className="security-section">
                    <h2>Security Settings</h2>
                    
                    <div className="security-option">
                        <h3>Two-Factor Authentication</h3>
                        <p>
                            Status: {user?.twoFactorEnabled ? 'Enabled' : 'Disabled'}
                        </p>
                        <button 
                            onClick={() => handleTwoFactorToggle(!user?.twoFactorEnabled)}
                        >
                            {user?.twoFactorEnabled ? 'Disable' : 'Enable'} 2FA
                        </button>
                    </div>

                    <div className="social-accounts">
                        <h3>Connected Accounts</h3>
                        {['google', 'facebook', 'twitter'].map(provider => (
                            <div key={provider} className="social-account-item">
                                <span>{provider.charAt(0).toUpperCase() + provider.slice(1)}</span>
                                <button
                                    onClick={() => 
                                        handleSocialAccountLink(
                                            provider, 
                                            user?.connectedAccounts?.[provider] ? 'unlink' : 'link'
                                        )
                                    }
                                >
                                    {user?.connectedAccounts?.[provider] ? 'Unlink' : 'Link'}
                                </button>
                            </div>
                        ))}
                    </div>
                </section>

                {/* Danger Zone */}
                <section className="danger-zone">
                    <h2>Danger Zone</h2>
                    <div className="danger-actions">
                        <button 
                            onClick={handleAccountDeletion}
                            className="danger-button"
                        >
                            Delete Account
                        </button>
                        <p>This action cannot be undone.</p>
                    </div>
                </section>
            </div>
        </div>
    );
};

export default ProfilePage;