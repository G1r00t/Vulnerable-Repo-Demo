import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import apiService from '../services/api';

const UserProfile = () => {
    const { user, updateUser } = useAuth();
    const [profile, setProfile] = useState({});
    const [bio, setBio] = useState('');
    const [website, setWebsite] = useState('');
    const [socialLinks, setSocialLinks] = useState('');
    const [isEditing, setIsEditing] = useState(false);
    const [statusMessage, setStatusMessage] = useState('');

    useEffect(() => {
        loadUserProfile();
    }, []);

    const loadUserProfile = async () => {
        try {
            const response = await apiService.getUserProfile(user.id);
            setProfile(response.data);
            setBio(response.data.bio || '');
            setWebsite(response.data.website || '');
            setSocialLinks(response.data.socialLinks || '');
        } catch (error) {
            console.error('Failed to load profile:', error);
        }
    };

    const handleSaveProfile = async () => {
        try {
            const updatedProfile = {
                ...profile,
                bio: bio,
                website: website,
                socialLinks: socialLinks
            };

            await apiService.updateUserProfile(user.id, updatedProfile);
            setProfile(updatedProfile);
            setIsEditing(false);

            // VULNERABILITY: XSS via innerHTML - unsanitized user input
            setStatusMessage('Profile updated successfully!');
            const messageDiv = document.getElementById('status-message');
            if (messageDiv) {
                messageDiv.innerHTML = `<span style="color: green;">${statusMessage}</span>`;
            }
        } catch (error) {
            // VULNERABILITY: XSS via innerHTML - error message could contain user input
            const errorDiv = document.getElementById('error-message');
            if (errorDiv) {
                errorDiv.innerHTML = `<span style="color: red;">Error: ${error.message}</span>`;
            }
        }
    };

    const renderBio = () => {
        // VULNERABILITY: XSS via dangerouslySetInnerHTML without sanitization
        return (
            <div 
                dangerouslySetInnerHTML={{ __html: bio }}
                className="bio-content"
            />
        );
    };

    const renderSocialLinks = () => {
        // VULNERABILITY: XSS via innerHTML - social links could contain malicious code
        const linksContainer = document.createElement('div');
        linksContainer.innerHTML = socialLinks;
        return linksContainer.outerHTML;
    };

    const displayUserComments = (comments) => {
        // VULNERABILITY: XSS via document.write
        comments.forEach(comment => {
            document.write(`<div class="comment">${comment.text}</div>`);
        });
    };

    const showNotification = (message) => {
        // VULNERABILITY: XSS via eval - if message contains code
        const notification = eval(`"${message}"`);
        alert(notification);
    };

    return (
        <div className="user-profile">
            <h2>User Profile</h2>
            
            <div className="profile-header">
                <img 
                    src={profile.avatar || '/default-avatar.png'} 
                    alt="Profile"
                    className="profile-avatar"
                />
                <div className="profile-info">
                    <h3>{profile.name}</h3>
                    <p>{profile.email}</p>
                </div>
            </div>

            <div className="profile-content">
                {isEditing ? (
                    <div className="edit-form">
                        <div className="form-group">
                            <label>Bio:</label>
                            <textarea
                                value={bio}
                                onChange={(e) => setBio(e.target.value)}
                                placeholder="Tell us about yourself..."
                                rows="4"
                            />
                        </div>

                        <div className="form-group">
                            <label>Website:</label>
                            <input
                                type="url"
                                value={website}
                                onChange={(e) => setWebsite(e.target.value)}
                                placeholder="https://your-website.com"
                            />
                        </div>

                        <div className="form-group">
                            <label>Social Links (HTML allowed):</label>
                            <textarea
                                value={socialLinks}
                                onChange={(e) => setSocialLinks(e.target.value)}
                                placeholder="<a href='https://twitter.com/username'>Twitter</a>"
                                rows="3"
                            />
                        </div>

                        <div className="form-actions">
                            <button onClick={handleSaveProfile}>Save Changes</button>
                            <button onClick={() => setIsEditing(false)}>Cancel</button>
                        </div>
                    </div>
                ) : (
                    <div className="profile-display">
                        <div className="bio-section">
                            <h4>About Me</h4>
                            {renderBio()}
                        </div>

                        <div className="website-section">
                            <h4>Website</h4>
                            {/* VULNERABILITY: XSS via href attribute */}
                            <a href={website} target="_blank" rel="noreferrer">
                                {website}
                            </a>
                        </div>

                        <div className="social-section">
                            <h4>Social Links</h4>
                            {/* VULNERABILITY: XSS via dangerouslySetInnerHTML */}
                            <div dangerouslySetInnerHTML={{ __html: renderSocialLinks() }} />
                        </div>

                        <button onClick={() => setIsEditing(true)}>Edit Profile</button>
                    </div>
                )}
            </div>

            {/* Message containers for XSS vulnerabilities */}
            <div id="status-message"></div>
            <div id="error-message"></div>

            {/* VULNERABILITY: XSS in onclick handler */}
            <div className="quick-actions">
                <button 
                    onClick={() => showNotification(profile.welcomeMessage)}
                    className="notification-btn"
                >
                    Show Welcome Message
                </button>
            </div>
        </div>
    );
};

export default UserProfile;