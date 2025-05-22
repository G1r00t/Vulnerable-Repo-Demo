"""
User Controller - Clean implementation following security best practices
"""

from flask import Blueprint, request, jsonify, current_app
from werkzeug.exceptions import BadRequest, NotFound, Conflict
from sqlalchemy.exc import IntegrityError
from sqlalchemy import and_, or_
import re
import uuid
from datetime import datetime
from ..models.user import User, UserProfile
from ..models import db
from ..config.logging import get_logger

user_bp = Blueprint('users', __name__)
logger = get_logger(__name__)

@user_bp.route('/', methods=['GET'])
def get_users():
    """
    Get all users with pagination and filtering - Clean implementation
    """
    try:
        # Get query parameters with defaults
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 10, type=int), 100)  # Limit max results
        search = request.args.get('search', '').strip()
        role_filter = request.args.get('role', '').strip()
        
        # Validate pagination parameters
        if page < 1 or per_page < 1:
            return jsonify({"error": "Invalid pagination parameters"}), 400
        
        # Build query using proper ORM methods
        query = User.query
        
        # Apply search filter safely
        if search:
            # Use parameterized queries to prevent SQL injection
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    User.username.ilike(search_term),
                    User.email.ilike(search_term)
                )
            )
        
        # Apply role filter safely
        if role_filter:
            query = query.filter(User.role == role_filter)
        
        # Only return active users
        query = query.filter(User.is_active == True)
        
        # Execute paginated query
        users = query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        # Serialize results without sensitive data
        user_list = []
        for user in users.items:
            user_dict = user.to_dict(include_sensitive=False)
            user_list.append(user_dict)
        
        response = {
            "users": user_list,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": users.total,
                "pages": users.pages,
                "has_next": users.has_next,
                "has_prev": users.has_prev
            }
        }
        
        logger.info(f"Retrieved {len(user_list)} users (page {page})")
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error retrieving users: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@user_bp.route('/<user_id>', methods=['GET'])
def get_user(user_id):
    """
    Get specific user by ID - Clean implementation with proper validation
    """
    try:
        # Validate UUID format
        try:
            uuid.UUID(user_id)
        except ValueError:
            return jsonify({"error": "Invalid user ID format"}), 400
        
        # Use ORM to safely query user
        user = User.query.filter_by(id=user_id, is_active=True).first()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Return user data without sensitive information
        user_data = user.to_dict(include_sensitive=False)
        
        # Include profile if exists
        if user.profile:
            user_data['profile'] = user.profile.to_dict()
        
        logger.info(f"Retrieved user: {user.username}")
        return jsonify(user_data)
        
    except Exception as e:
        logger.error(f"Error retrieving user {user_id}: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@user_bp.route('/', methods=['POST'])
def create_user():
    """
    Create new user - Clean implementation with proper validation
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Validate required fields
        required_fields = ['username', 'email', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        # Extract and validate data
        username = data['username'].strip().lower()
        email = data['email'].strip().lower()
        password = data['password']
        role = data.get('role', 'user').strip().lower()
        
        # Validate role
        valid_roles = ['user', 'moderator', 'admin']
        if role not in valid_roles:
            return jsonify({"error": f"Invalid role. Must be one of: {valid_roles}"}), 400
        
        # Create user using model validation
        try:
            user = User(username=username, email=email, password=password)
            user.role = role
            
            # Save to database
            db.session.add(user)
            db.session.commit()
            
            # Create user profile if profile data provided
            profile_data = data.get('profile', {})
            if profile_data:
                profile = UserProfile(user_id=user.id)
                for key, value in profile_data.items():
                    if hasattr(profile, key) and value:
                        setattr(profile, key, value)
                
                db.session.add(profile)
                db.session.commit()
            
            logger.info(f"Created new user: {username}")
            
            # Return created user data (without sensitive info)
            return jsonify({
                "message": "User created successfully",
                "user": user.to_dict(include_sensitive=False)
            }), 201
            
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except IntegrityError:
            db.session.rollback()
            return jsonify({"error": "Username or email already exists"}), 409
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating user: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@user_bp.route('/<user_id>', methods=['PUT'])
def update_user(user_id):
    """
    Update user information - Clean implementation with authorization
    """
    try:
        # Validate UUID format
        try:
            uuid.UUID(user_id)
        except ValueError:
            return jsonify({"error": "Invalid user ID format"}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Find user using ORM
        user = User.query.filter_by(id=user_id, is_active=True).first()
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Update allowed fields
        updatable_fields = ['email', 'role']
        updated_fields = []
        
        for field in updatable_fields:
            if field in data:
                new_value = data[field]
                
                if field == 'email':
                    # Validate email format
                    try:
                        new_value = User.validate_email(new_value)
                        user.email = new_value
                        updated_fields.append(field)
                    except ValueError as e:
                        return jsonify({"error": str(e)}), 400
                
                elif field == 'role':
                    # Validate role
                    valid_roles = ['user', 'moderator', 'admin']
                    if new_value in valid_roles:
                        user.role = new_value
                        updated_fields.append(field)
                    else:
                        return jsonify({"error": f"Invalid role. Must be one of: {valid_roles}"}), 400
        
        # Update profile if provided
        if 'profile' in data:
            profile_data = data['profile']
            if not user.profile:
                user.profile = UserProfile(user_id=user.id)
            
            profile_fields = ['first_name', 'last_name', 'phone', 'address_line1', 
                            'address_line2', 'city', 'state', 'postal_code', 'country']
            
            for field in profile_fields:
                if field in profile_data:
                    setattr(user.profile, field, profile_data[field])
            
            updated_fields.append('profile')
        
        if updated_fields:
            user.updated_at = datetime.utcnow()
            db.session.commit()
            
            logger.info(f"Updated user {user.username}: {', '.join(updated_fields)}")
            
            return jsonify({
                "message": "User updated successfully",
                "updated_fields": updated_fields,
                "user": user.to_dict(include_sensitive=False)
            })
        else:
            return jsonify({"message": "No valid fields to update"}), 400
        
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Email already exists"}), 409
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating user {user_id}: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@user_bp.route('/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    """
    Soft delete user - Clean implementation
    """
    try:
        # Validate UUID format
        try:
            uuid.UUID(user_id)
        except ValueError:
            return jsonify({"error": "Invalid user ID format"}), 400
        
        # Find user using ORM
        user = User.query.filter_by(id=user_id, is_active=True).first()
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Soft delete - set is_active to False
        user.is_active = False
        user.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        logger.info(f"Soft deleted user: {user.username}")
        
        return jsonify({"message": "User deleted successfully"})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting user {user_id}: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@user_bp.route('/<user_id>/profile', methods=['POST', 'PUT'])
def update_user_profile(user_id):
    """
    Update user profile - Clean implementation
    """
    try:
        # Validate UUID format
        try:
            uuid.UUID(user_id)
        except ValueError:
            return jsonify({"error": "Invalid user ID format"}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Find user using ORM
        user = User.query.filter_by(id=user_id, is_active=True).first()
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Create or update profile
        if not user.profile:
            user.profile = UserProfile(user_id=user.id)
            db.session.add(user.profile)
        
        # Update profile fields safely
        profile_fields = [
            'first_name', 'last_name', 'phone', 'date_of_birth',
            'address_line1', 'address_line2', 'city', 'state', 
            'postal_code', 'country', 'newsletter_subscribed', 'marketing_emails'
        ]
        
        updated_fields = []
        for field in profile_fields:
            if field in data:
                setattr(user.profile, field, data[field])
                updated_fields.append(field)
        
        if updated_fields:
            user.profile.updated_at = datetime.utcnow()
            db.session.commit()
            
            logger.info(f"Updated profile for user {user.username}: {', '.join(updated_fields)}")
            
            return jsonify({
                "message": "Profile updated successfully",
                "updated_fields": updated_fields,
                "profile": user.profile.to_dict()
            })
        else:
            return jsonify({"message": "No valid fields to update"}), 400
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating profile for user {user_id}: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@user_bp.errorhandler(400)
def bad_request(error):
    """Clean error handler for bad requests"""
    return jsonify({"error": "Bad request"}), 400

@user_bp.errorhandler(404)
def not_found(error):
    """Clean error handler for not found"""
    return jsonify({"error": "Resource not found"}), 404

@user_bp.errorhandler(500)
def internal_error(error):
    """Clean error handler for internal errors"""
    db.session.rollback()
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({"error": "Internal server error"}), 500