import os
import unittest
from unittest.mock import patch, MagicMock
from flask import get_flashed_messages, session
from sqlalchemy.exc import SQLAlchemyError

# Add the project root to the Python path to allow importing flaskblog
import sys
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from flask import url_for # Added for use in assertions
from flaskblog import app, db, User, Post, Category, Comment # Added Comment model
from flaskblog import save_post_image # Ensure this is importable
from PIL import Image, UnidentifiedImageError as PillowUnidentifiedImageError
from werkzeug.datastructures import FileStorage # For mocking file uploads, used in other tests


class FlaskBlogTestCase(unittest.TestCase):

    def setUp(self):
        """Set up test variables."""
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing forms
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['SECRET_KEY'] = 'test_secret_key'
        self.app = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()
        self.create_test_user_and_category()

    def tearDown(self):
        """Executed after each test."""
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def login(self, email, password):
        return self.app.post('/login', data=dict(
            email=email,
            password=password
        ), follow_redirects=True)

    def logout(self):
        return self.app.get('/logout', follow_redirects=True)

    def create_test_user_and_category(self):
        # Create a test user
        user = User(username='testuser', email='test@example.com', password='password')
        db.session.add(user)
        # Create a test category
        category = Category(name='Test Category', description='A category for testing')
        db.session.add(category)
        db.session.commit()

    # --- Helper to get flashed messages ---
    def get_flashed_messages_dict(self):
        # In newer Flask versions, flashed messages are tuples (category, message)
        # This helper simplifies checking if a message (regardless of category) exists.
        # For more specific tests, you might want to check category too.
        flashes = session.get('_flashes', [])
        return [message for category, message in flashes]

    # ----------------------------------------
    # SECTION 1: Tests for save_post_image
    # ----------------------------------------

    @patch('flaskblog.Image.open')
    @patch('os.path.splitext', return_value=('filename', '.png')) # Mock splitext
    @patch('secrets.token_hex', return_value='randomhex') # Mock token_hex
    @patch('flaskblog.app.logger.error') # Mock logger
    def test_save_post_image_unidentified_image_error(self, mock_logger_error, mock_token_hex, mock_splitext, mock_image_open):
        mock_image_open.side_effect = PillowUnidentifiedImageError("Cannot identify image file")
        mock_form_picture = MagicMock()
        mock_form_picture.filename = 'test.png'

        filename, error = save_post_image(mock_form_picture)

        self.assertIsNone(filename)
        self.assertEqual(error, "Invalid image file: The provided file is not a recognized image format.")
        mock_logger_error.assert_not_called() # Specific PillowUnidentifiedImageError is handled, not logged as a generic error

    @patch('flaskblog.Image.open')
    @patch('os.path.splitext', return_value=('filename', '.png'))
    @patch('secrets.token_hex', return_value='randomhex')
    @patch('flaskblog.app.logger.error')
    def test_save_post_image_io_error_on_open(self, mock_logger_error, mock_token_hex, mock_splitext, mock_image_open):
        mock_image_open.side_effect = IOError("File not found")
        mock_form_picture = MagicMock()
        mock_form_picture.filename = 'test.png'

        filename, error = save_post_image(mock_form_picture)

        self.assertIsNone(filename)
        self.assertEqual(error, "Invalid image file: Could not open or read the image.")
        mock_logger_error.assert_not_called() # IOError on open is handled, not logged as a generic error by save_post_image

    @patch('flaskblog.Image.open')
    @patch('os.path.splitext', return_value=('filename', '.png'))
    @patch('secrets.token_hex', return_value='randomhex')
    @patch('flaskblog.app.logger.error')
    def test_save_post_image_error_on_thumbnail(self, mock_logger_error, mock_token_hex, mock_splitext, mock_image_open):
        mock_img_instance = MagicMock()
        mock_img_instance.thumbnail.side_effect = Exception("Thumbnail failed")
        mock_image_open.return_value = mock_img_instance
        mock_form_picture = MagicMock()
        mock_form_picture.filename = 'test.png'

        filename, error = save_post_image(mock_form_picture)

        self.assertIsNone(filename)
        self.assertEqual(error, "Failed to resize image. The image might be corrupted or in an unsupported format.")
        mock_logger_error.assert_called_once_with("Pillow thumbnail error: Thumbnail failed")

    @patch('flaskblog.Image.open')
    @patch('os.path.join') # Mock os.path.join to control the save path
    @patch('os.path.splitext', return_value=('filename', '.png'))
    @patch('secrets.token_hex', return_value='randomhex')
    @patch('flaskblog.app.logger.error')
    def test_save_post_image_error_on_save(self, mock_logger_error, mock_token_hex, mock_splitext, mock_os_join, mock_image_open):
        mock_img_instance = MagicMock()
        mock_img_instance.save.side_effect = Exception("Save failed")
        mock_image_open.return_value = mock_img_instance
        # Ensure os.path.join returns a valid-looking path for the logging inside save_post_image
        mock_os_join.return_value = "/fake/path/randomhex.png"
        mock_form_picture = MagicMock()
        mock_form_picture.filename = 'test.png'

        filename, error = save_post_image(mock_form_picture)

        self.assertIsNone(filename)
        self.assertEqual(error, "Failed to save image. Please try again later.")
        mock_logger_error.assert_called_once_with("Pillow save error: Save failed")

    @patch('flaskblog.Image.open')
    @patch('os.path.join')
    @patch('os.path.splitext', return_value=('filename', '.png'))
    @patch('secrets.token_hex', return_value='randomhex')
    def test_save_post_image_success(self, mock_token_hex, mock_splitext, mock_os_join, mock_image_open):
        mock_img_instance = MagicMock()
        mock_image_open.return_value = mock_img_instance
        mock_os_join.return_value = "/fake/path/randomhex.png"
        mock_form_picture = MagicMock()
        mock_form_picture.filename = 'test.png'

        # Create a dummy file for Image.open to work with if it's not fully mocked for size etc.
        # However, since we mock the instance `i` directly, this might not be needed.
        # For this test, we assume Image.open, thumbnail, and save are successful.

        filename, error = save_post_image(mock_form_picture)

        self.assertEqual(filename, "randomhex.png")
        self.assertIsNone(error)
        mock_img_instance.thumbnail.assert_called_once_with((800, 800))
        mock_img_instance.save.assert_called_once_with("/fake/path/randomhex.png")

    # -----------------------------------------------------
    # SECTION 2: Tests for new_post route (image errors)
    # -----------------------------------------------------
    @patch('flaskblog.save_post_image')
    def test_new_post_image_save_fails(self, mock_save_post_image):
        self.login('test@example.com', 'password')
        mock_save_post_image.return_value = (None, "Mocked image save error")

        # Create a mock file object for form.picture.data
        mock_file = MagicMock(spec=FileStorage) # Use Werkzeug's FileStorage for type hint if available
        mock_file.filename = "test_image.png"

        category = Category.query.first() # Get the test category

        response = self.app.post('/post/new', data={
            'title': 'Test Post Title',
            'content': 'Test post content that is long enough.',
            'category': category.id,
            'tags': 'test, tag',
            'status': 'published',
            'picture': (mock_file, 'test_image.png') # Simulate file upload
        }, content_type='multipart/form-data', follow_redirects=True)

        self.assertEqual(response.status_code, 200) # Should re-render the form

        # Check flashed messages
        flashed_messages = self.get_flashed_messages_dict()
        self.assertIn("Image upload failed: Mocked image save error", flashed_messages)

        # Check that post was not created
        post = Post.query.filter_by(title='Test Post Title').first()
        self.assertIsNone(post)
        self.logout()

    # --------------------------------------------------------
    # SECTION 3: Tests for update_post route (image errors)
    # --------------------------------------------------------
    @patch('flaskblog.save_post_image')
    @patch('os.remove') # Mock os.remove to prevent actual file deletion attempts
    def test_update_post_image_save_fails(self, mock_os_remove, mock_save_post_image):
        self.login('test@example.com', 'password')
        user = User.query.filter_by(email='test@example.com').first()
        category = Category.query.first()

        # Create an initial post
        initial_post = Post(title="Initial Post", content="Initial content.", author=user, category_id=category.id)
        db.session.add(initial_post)
        db.session.commit()

        mock_save_post_image.return_value = (None, "Mocked update image error")

        mock_file = MagicMock(spec=FileStorage)
        mock_file.filename = "updated_image.png"

        response = self.app.post(f'/post/{initial_post.id}/update', data={
            'title': 'Updated Post Title',
            'content': 'Updated post content.',
            'category': category.id,
            'tags': 'update, test',
            'status': 'published',
            'picture': (mock_file, 'updated_image.png')
        }, content_type='multipart/form-data', follow_redirects=True)

        self.assertEqual(response.status_code, 200) # Should re-render form

        flashed_messages = self.get_flashed_messages_dict()
        self.assertIn("Image upload failed: Mocked update image error", flashed_messages)

        # Check that post was not updated with the new title (or image)
        updated_post = Post.query.get(initial_post.id)
        self.assertEqual(updated_post.title, "Initial Post") # Title should not have changed
        self.assertIsNone(updated_post.image_file) # Assuming initial post had no image
        mock_os_remove.assert_not_called() # os.remove should not be called if new image save failed
        self.logout()

    # --------------------------------------------------
    # SECTION 4: Tests for post() route error handling
    # --------------------------------------------------
    @patch('flaskblog.db.session.commit', side_effect=SQLAlchemyError("Simulated DB commit error"))
    @patch('flaskblog.db.session.rollback')
    @patch('flaskblog.app.logger.error')
    def test_post_route_sqlalchemy_error(self, mock_logger_error, mock_db_rollback, mock_db_commit):
        self.login('test@example.com', 'password')
        user = User.query.filter_by(email='test@example.com').first()
        category = Category.query.first()
        # Create a post to view
        test_post = Post(title="DB Error Test Post", content="Content", author=user, category_id=category.id, status="published")
        db.session.add(test_post)
        db.session.commit() # Initial commit should be fine

        # Now, when viewing the post, the mocked commit (for view count) will raise an error
        response = self.app.get(f'/post/{test_post.id}', follow_redirects=False) # False to check redirect location

        self.assertEqual(response.status_code, 302) # Should redirect
        self.assertTrue(response.location.endswith(url_for('home'))) # Check redirect to home

        flashed_messages = self.get_flashed_messages_dict()
        self.assertIn("A database error occurred while trying to load the post. Please try again later.", flashed_messages)

        mock_db_commit.assert_called_once() # The commit for view count
        mock_db_rollback.assert_called_once() # Rollback should be called
        mock_logger_error.assert_called_once()
        self.assertIn(f"Database error displaying post {test_post.id}", mock_logger_error.call_args[0][0])
        self.logout()

    @patch('flaskblog.get_sidebar_data', side_effect=Exception("Simulated unexpected error"))
    @patch('flaskblog.app.logger.error')
    def test_post_route_generic_exception(self, mock_logger_error, mock_get_sidebar_data):
        self.login('test@example.com', 'password')
        user = User.query.filter_by(email='test@example.com').first()
        category = Category.query.first()
        test_post = Post(title="Generic Error Test Post", content="Content", author=user, category_id=category.id, status="published")
        db.session.add(test_post)
        db.session.commit()

        # The mocked get_sidebar_data will raise an error when rendering the post
        response = self.app.get(f'/post/{test_post.id}', follow_redirects=False)

        self.assertEqual(response.status_code, 302) # Should redirect
        self.assertTrue(response.location.endswith(url_for('home')))

        flashed_messages = self.get_flashed_messages_dict()
        self.assertIn("An unexpected error occurred while loading the post. Please try again later.", flashed_messages)

        mock_logger_error.assert_called_once()
        self.assertIn(f"Unexpected error displaying post {test_post.id}", mock_logger_error.call_args[0][0])
        # Check that exc_info=True was passed to the logger
        self.assertEqual(mock_logger_error.call_args[1].get('exc_info'), True)
        self.logout()


if __name__ == '__main__':
    unittest.main()

# Note: Conceptual tests for client-side JS validation would be described separately
# as they are not implemented in this Python unit test file.


    # --------------------------------------------------
    # SECTION 5: Tests for add_comment functionality
    # --------------------------------------------------

    def test_add_comment_success(self):
        self.login('test@example.com', 'password')
        user = User.query.filter_by(email='test@example.com').first()
        category = Category.query.first()

        # Create a test post
        test_post = Post(title="Comment Test Post", content="Some content", author=user, category_id=category.id)
        db.session.add(test_post)
        db.session.commit()

        response = self.app.post(url_for('add_comment', post_id=test_post.id), data={
            'content': 'This is a test comment'
            # parent_id is not provided for a top-level comment
        }, follow_redirects=False) # Test redirect explicitly

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith(url_for('post', post_id=test_post.id, _anchor='comments-section')))

        flashed_messages = self.get_flashed_messages_dict()
        self.assertIn('Your comment has been posted!', flashed_messages)

        comment = Comment.query.filter_by(post_id=test_post.id, user_id=user.id).first()
        self.assertIsNotNone(comment)
        self.assertEqual(comment.content, 'This is a test comment')
        self.assertIsNone(comment.parent_id)
        self.logout()

    def test_add_reply_success(self):
        self.login('test@example.com', 'password')
        user = User.query.filter_by(email='test@example.com').first()
        category = Category.query.first()

        test_post = Post(title="Reply Test Post", content="Content for reply", author=user, category_id=category.id)
        db.session.add(test_post)
        db.session.commit()

        parent_comment = Comment(content="Parent comment", user_id=user.id, post_id=test_post.id)
        db.session.add(parent_comment)
        db.session.commit()

        response = self.app.post(url_for('add_comment', post_id=test_post.id), data={
            'content': 'This is a test reply',
            'parent_id': str(parent_comment.id) # Ensure parent_id is sent as string, like form data
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith(url_for('post', post_id=test_post.id, _anchor='comments-section')))

        flashed_messages = self.get_flashed_messages_dict()
        self.assertIn('Your comment has been posted!', flashed_messages)

        reply = Comment.query.filter_by(content='This is a test reply').first()
        self.assertIsNotNone(reply)
        self.assertEqual(reply.user_id, user.id)
        self.assertEqual(reply.post_id, test_post.id)
        self.assertEqual(reply.parent_id, parent_comment.id)
        self.logout()

    def test_add_comment_not_logged_in(self):
        user = User.query.filter_by(email='test@example.com').first() # User exists but not logged in
        category = Category.query.first()
        test_post = Post(title="Auth Test Post", content="Content", author=user, category_id=category.id)
        db.session.add(test_post)
        db.session.commit()

        response = self.app.post(url_for('add_comment', post_id=test_post.id), data={
            'content': 'Attempting comment while not logged in'
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith(url_for('login'))) # Should redirect to login

        comment_count = Comment.query.filter_by(post_id=test_post.id).count()
        self.assertEqual(comment_count, 0)

    def test_add_comment_empty_content(self):
        self.login('test@example.com', 'password')
        user = User.query.filter_by(email='test@example.com').first()
        category = Category.query.first()
        test_post = Post(title="Validation Test Post", content="Content", author=user, category_id=category.id)
        db.session.add(test_post)
        db.session.commit()

        response = self.app.post(url_for('add_comment', post_id=test_post.id), data={
            'content': '' # Empty content
        }, follow_redirects=False) # Check redirect and flashed message before redirect

        self.assertEqual(response.status_code, 302) # Should still redirect to post page
        self.assertTrue(response.location.endswith(url_for('post', post_id=test_post.id, _anchor='comments-section')))

        flashed_messages = self.get_flashed_messages_dict()
        # Based on the add_comment implementation, it flashes specific field errors
        self.assertIn("Error in Content: This field is required.", flashed_messages)
        # Or a more generic one if specific field detection fails in test / form setup
        # self.assertIn('Error posting comment. Please check your input.', flashed_messages)


        comment_count = Comment.query.filter_by(post_id=test_post.id).count()
        self.assertEqual(comment_count, 0)
        self.logout()
