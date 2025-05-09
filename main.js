// Main JavaScript for Polar Social Platform
document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const splashScreen = document.getElementById('splash-screen');
    const appContainer = document.getElementById('app-container');
    const authContainer = document.getElementById('auth-container');
    const themeToggle = document.getElementById('theme-toggle');
    const toggleSidebar = document.getElementById('toggle-sidebar');
    const sidebar = document.querySelector('.sidebar');
    const postContainer = document.getElementById('posts-container');
    const createPostBtn = document.getElementById('create-post-btn');
    const newPostText = document.getElementById('new-post-text');
    const chatWindow = document.getElementById('chat-window');
    const closeChat = document.querySelector('.close-chat');
    const chatMessages = document.getElementById('chat-messages');
    const chatInput = document.getElementById('chat-input');
    const sendMessageBtn = document.querySelector('.send-message');
    const logoutButton = document.getElementById('logout-btn');
    const loginForm = document.getElementById('login-form');
    const signupForm = document.getElementById('signup-form');
    const switchToSignup = document.getElementById('switch-to-signup');
    const switchToLogin = document.getElementById('switch-to-login');
    const notificationBell = document.getElementById('notification-bell');
    const notificationPanel = document.getElementById('notification-panel');

    // Global variables
    let currentUser = null;
    let darkMode = localStorage.getItem('darkMode') === 'true';
    let activeChat = null;
    let posts = JSON.parse(localStorage.getItem('posts')) || [];
    let notifications = JSON.parse(localStorage.getItem('notifications')) || [];
    
    // Apply saved theme on page load
    if (darkMode) {
        document.body.classList.add('dark-mode');
    }

    // Initialize the application
    init();

    // Initialization function
    function init() {
        // Show splash screen for 2 seconds
        setTimeout(() => {
            splashScreen.classList.add('fade-out');
            setTimeout(() => {
                splashScreen.style.display = 'none';
                
                // Check if user is logged in
                const savedUser = localStorage.getItem('currentUser');
                if (savedUser) {
                    currentUser = JSON.parse(savedUser);
                    showApp();
                } else {
                    showAuth();
                }
            }, 500);
        }, 2000);

        // Attach event listeners
        attachEventListeners();
        
        // Load and display posts
        displayPosts();
        
        // Load and display notifications
        displayNotifications();
    }

    // Attach all event listeners
    function attachEventListeners() {
        // Theme toggle
        themeToggle.addEventListener('click', toggleTheme);
        
        // Sidebar toggle
        if (toggleSidebar) {
            toggleSidebar.addEventListener('click', () => {
                sidebar.classList.toggle('collapsed');
            });
        }
        
        // Create post
        if (createPostBtn) {
            createPostBtn.addEventListener('click', createPost);
        }
        
        // Chat window
        if (closeChat) {
            closeChat.addEventListener('click', () => {
                chatWindow.classList.remove('active');
            });
        }
        
        if (sendMessageBtn) {
            sendMessageBtn.addEventListener('click', sendMessage);
            chatInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    sendMessage();
                }
            });
        }
        
        // Auth forms
        if (loginForm) {
            loginForm.addEventListener('submit', handleLogin);
        }
        
        if (signupForm) {
            signupForm.addEventListener('submit', handleSignup);
        }
        
        // Switch between login and signup
        if (switchToSignup) {
            switchToSignup.addEventListener('click', (e) => {
                e.preventDefault();
                document.querySelector('.login-container').style.display = 'none';
                document.querySelector('.signup-container').style.display = 'block';
            });
        }
        
        if (switchToLogin) {
            switchToLogin.addEventListener('click', (e) => {
                e.preventDefault();
                document.querySelector('.signup-container').style.display = 'none';
                document.querySelector('.login-container').style.display = 'block';
            });
        }
        
        // Logout
        if (logoutButton) {
            logoutButton.addEventListener('click', logout);
        }
        
        // Notification bell
        if (notificationBell) {
            notificationBell.addEventListener('click', toggleNotifications);
        }
        
        // Add event delegation for post interactions
        if (postContainer) {
            postContainer.addEventListener('click', handlePostInteractions);
        }
    }

    // Toggle theme between light and dark mode
    function toggleTheme() {
        darkMode = !darkMode;
        document.body.classList.toggle('dark-mode');
        localStorage.setItem('darkMode', darkMode);
        
        // Update icon
        themeToggle.innerHTML = darkMode ? 
            '<i class="fas fa-sun"></i>' : 
            '<i class="fas fa-moon"></i>';
    }

    // Show the main application
    function showApp() {
        authContainer.style.display = 'none';
        appContainer.style.display = 'block';
        
        // Update user info in the UI
        const userDisplay = document.getElementById('user-display');
        if (userDisplay) {
            userDisplay.textContent = currentUser.username;
        }
        
        // Fetch fresh data
        fetchPosts();
        fetchNotifications();
    }

    // Show authentication screen
    function showAuth() {
        appContainer.style.display = 'none';
        authContainer.style.display = 'flex';
        document.querySelector('.login-container').style.display = 'block';
        document.querySelector('.signup-container').style.display = 'none';
    }

    // Handle login form submission
    async function handleLogin(e) {
        e.preventDefault();
        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;
        
        try {
            const response = await fetch('php/login.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });
            
            const data = await response.json();
            
            if (data.success) {
                currentUser = data.user;
                localStorage.setItem('currentUser', JSON.stringify(currentUser));
                showApp();
            } else {
                showError('login-error', data.message || 'Invalid credentials');
            }
        } catch (error) {
            console.error('Login error:', error);
            showError('login-error', 'An error occurred during login');
        }
    }

    // Handle signup form submission
    async function handleSignup(e) {
        e.preventDefault();
        const username = document.getElementById('signup-username').value;
        const email = document.getElementById('signup-email').value;
        const password = document.getElementById('signup-password').value;
        const confirmPassword = document.getElementById('signup-confirm-password').value;
        
        // Basic validation
        if (password !== confirmPassword) {
            showError('signup-error', 'Passwords do not match');
            return;
        }
        
        try {
            const response = await fetch('php/signup.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, email, password })
            });
            
            const data = await response.json();
            
            if (data.success) {
                // Show success message and switch to login
                document.getElementById('signup-success').textContent = 'Account created successfully! You can now log in.';
                document.getElementById('signup-success').style.display = 'block';
                
                setTimeout(() => {
                    document.querySelector('.signup-container').style.display = 'none';
                    document.querySelector('.login-container').style.display = 'block';
                    document.getElementById('signup-success').style.display = 'none';
                    signupForm.reset();
                }, 2000);
            } else {
                showError('signup-error', data.message || 'Error creating account');
            }
        } catch (error) {
            console.error('Signup error:', error);
            showError('signup-error', 'An error occurred during signup');
        }
    }

    // Show error message
    function showError(elementId, message) {
        const errorElement = document.getElementById(elementId);
        if (errorElement) {
            errorElement.textContent = message;
            errorElement.style.display = 'block';
            
            // Hide after 3 seconds
            setTimeout(() => {
                errorElement.style.display = 'none';
            }, 3000);
        }
    }

    // Create a new post
    async function createPost() {
        const postContent = newPostText.value.trim();
        
        if (!postContent) return;
        
        const newPost = {
            id: Date.now(),
            content: postContent,
            author: currentUser.username,
            authorId: currentUser.id,
            timestamp: new Date().toISOString(),
            likes: 0,
            comments: []
        };
        
        try {
            const response = await fetch('php/create_post.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ 
                    userId: currentUser.id,
                    content: postContent
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                posts.unshift(data.post); // Use the post returned from server
                localStorage.setItem('posts', JSON.stringify(posts));
                displayPosts();
                newPostText.value = '';
            } else {
                console.error('Error creating post:', data.message);
            }
        } catch (error) {
            console.error('Error creating post:', error);
            // Fallback to local storage if server is not available
            posts.unshift(newPost);
            localStorage.setItem('posts', JSON.stringify(posts));
            displayPosts();
            newPostText.value = '';
        }
    }

    // Display all posts
    function displayPosts() {
        if (!postContainer) return;
        
        postContainer.innerHTML = '';
        
        if (posts.length === 0) {
            postContainer.innerHTML = '<div class="no-posts">No posts yet. Be the first to share something!</div>';
            return;
        }
        
        posts.forEach(post => {
            const postElement = document.createElement('div');
            postElement.classList.add('post');
            postElement.dataset.postId = post.id;
            
            const likedClass = post.likedBy && post.likedBy.includes(currentUser.id) ? 'liked' : '';
            
            postElement.innerHTML = `
                <div class="post-header">
                    <img src="images/avatars/default.png" alt="Profile" class="post-avatar">
                    <div class="post-info">
                        <div class="post-author">${post.author}</div>
                        <div class="post-time">${formatTime(post.timestamp)}</div>
                    </div>
                </div>
                <div class="post-content">${post.content}</div>
                <div class="post-actions">
                    <button class="like-btn ${likedClass}" data-action="like">
                        <i class="fas fa-heart"></i> <span>${post.likes || 0}</span>
                    </button>
                    <button class="comment-btn" data-action="comment">
                        <i class="fas fa-comment"></i> <span>${post.comments ? post.comments.length : 0}</span>
                    </button>
                    <button class="share-btn" data-action="share">
                        <i class="fas fa-share"></i>
                    </button>
                </div>
                <div class="comments-section" style="display: none;">
                    <div class="comments-list">
                        ${renderComments(post.comments || [])}
                    </div>
                    <div class="add-comment">
                        <input type="text" placeholder="Add a comment..." class="comment-input">
                        <button class="submit-comment" data-action="submit-comment">
                            <i class="fas fa-paper-plane"></i>
                        </button>
                    </div>
                </div>
            `;
            
            postContainer.appendChild(postElement);
        });
    }

    // Render comments for a post
    function renderComments(comments) {
        if (!comments || comments.length === 0) {
            return '<div class="no-comments">No comments yet</div>';
        }
        
        return comments.map(comment => `
            <div class="comment">
                <div class="comment-header">
                    <img src="images/avatars/default.png" alt="Profile" class="comment-avatar">
                    <div class="comment-author">${comment.author}</div>
                </div>
                <div class="comment-content">${comment.content}</div>
                <div class="comment-time">${formatTime(comment.timestamp)}</div>
            </div>
        `).join('');
    }

    // Handle post interactions (likes, comments, shares)
    async function handlePostInteractions(e) {
        const target = e.target.closest('button');
        if (!target) return;
        
        const action = target.dataset.action;
        const postElement = target.closest('.post');
        const postId = parseInt(postElement.dataset.postId);
        const postIndex = posts.findIndex(p => p.id === postId);
        
        if (postIndex === -1) return;
        
        switch (action) {
            case 'like':
                await handleLike(postId, postIndex, target);
                break;
            case 'comment':
                toggleComments(postElement);
                break;
            case 'share':
                sharePost(posts[postIndex]);
                break;
            case 'submit-comment':
                submitComment(postElement, postId, postIndex);
                break;
        }
    }

    // Handle liking a post
    async function handleLike(postId, postIndex, likeButton) {
        try {
            const response = await fetch('php/like_post.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ 
                    userId: currentUser.id,
                    postId: postId
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                // Update with server data
                posts[postIndex].likes = data.likes;
                posts[postIndex].likedBy = data.likedBy;
            } else {
                // Fallback to local toggle
                if (!posts[postIndex].likedBy) {
                    posts[postIndex].likedBy = [];
                }
                
                const alreadyLiked = posts[postIndex].likedBy.includes(currentUser.id);
                
                if (alreadyLiked) {
                    posts[postIndex].likes--;
                    posts[postIndex].likedBy = posts[postIndex].likedBy.filter(id => id !== currentUser.id);
                    likeButton.classList.remove('liked');
                } else {
                    posts[postIndex].likes++;
                    posts[postIndex].likedBy.push(currentUser.id);
                    likeButton.classList.add('liked');
                }
            }
            
            // Update the like count in the UI
            const likeCount = likeButton.querySelector('span');
            likeCount.textContent = posts[postIndex].likes;
            
            // Save to localStorage
            localStorage.setItem('posts', JSON.stringify(posts));
            
        } catch (error) {
            console.error('Error liking post:', error);
            // Implement local fallback here
        }
    }

    // Toggle comments section visibility
    function toggleComments(postElement) {
        const commentsSection = postElement.querySelector('.comments-section');
        commentsSection.style.display = commentsSection.style.display === 'none' ? 'block' : 'none';
    }

    // Submit a new comment
    async function submitComment(postElement, postId, postIndex) {
        const commentInput = postElement.querySelector('.comment-input');
        const commentContent = commentInput.value.trim();
        
        if (!commentContent) return;
        
        const newComment = {
            id: Date.now(),
            content: commentContent,
            author: currentUser.username,
            authorId: currentUser.id,
            timestamp: new Date().toISOString()
        };
        
        try {
            const response = await fetch('php/add_comment.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ 
                    userId: currentUser.id,
                    postId: postId,
                    content: commentContent
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                // Use server data
                if (!posts[postIndex].comments) {
                    posts[postIndex].comments = [];
                }
                posts[postIndex].comments.push(data.comment);
            } else {
                // Fallback to local
                if (!posts[postIndex].comments) {
                    posts[postIndex].comments = [];
                }
                posts[postIndex].comments.push(newComment);
            }
            
            // Update the UI
            const commentsList = postElement.querySelector('.comments-list');
            commentsList.innerHTML = renderComments(posts[postIndex].comments);
            
            // Update comment count
            const commentCount = postElement.querySelector('.comment-btn span');
            commentCount.textContent = posts[postIndex].comments.length;
            
            // Clear input
            commentInput.value = '';
            
            // Save to localStorage
            localStorage.setItem('posts', JSON.stringify(posts));
            
        } catch (error) {
            console.error('Error adding comment:', error);
            // Implement local fallback
            if (!posts[postIndex].comments) {
                posts[postIndex].comments = [];
            }
            posts[postIndex].comments.push(newComment);
            
            // Update UI locally
            const commentsList = postElement.querySelector('.comments-list');
            commentsList.innerHTML = renderComments(posts[postIndex].comments);
            
            // Update comment count
            const commentCount = postElement.querySelector('.comment-btn span');
            commentCount.textContent = posts[postIndex].comments.length;
            
            // Clear input
            commentInput.value = '';
            
            // Save to localStorage
            localStorage.setItem('posts', JSON.stringify(posts));
        }
    }

    // Share a post
    function sharePost(post) {
        // Create a shareable link
        const shareUrl = `${window.location.origin}${window.location.pathname}?post=${post.id}`;
        
        // Check if Web Share API is available
        if (navigator.share) {
            navigator.share({
                title: 'Polar Social Post',
                text: `${post.author} shared: ${post.content.substring(0, 50)}...`,
                url: shareUrl
            })
            .catch(error => console.error('Error sharing:', error));
        } else {
            // Fallback to copying to clipboard
            navigator.clipboard.writeText(shareUrl)
                .then(() => {
                    alert('Link copied to clipboard!');
                })
                .catch(err => {
                    console.error('Failed to copy:', err);
                    // Manual fallback
                    prompt('Copy this link to share the post:', shareUrl);
                });
        }
    }

    // Send a chat message
    function sendMessage() {
        if (!activeChat) return;
        
        const messageText = chatInput.value.trim();
        if (!messageText) return;
        
        const newMessage = {
            sender: currentUser.id,
            recipient: activeChat.id,
            content: messageText,
            timestamp: new Date().toISOString()
        };
        
        // Add message to UI
        appendMessage(newMessage, true);
        
        // Clear input
        chatInput.value = '';
        
        // Send to server
        fetch('php/send_message.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(newMessage)
        })
        .catch(error => console.error('Error sending message:', error));
    }

    // Append a message to the chat window
    function appendMessage(message, isOutgoing = false) {
        const messageElement = document.createElement('div');
        messageElement.classList.add('message');
        messageElement.classList.add(isOutgoing ? 'outgoing' : 'incoming');
        
        messageElement.innerHTML = `
            <div class="message-bubble">
                ${message.content}
            </div>
            <div class="message-time">${formatTime(message.timestamp)}</div>
        `;
        
        chatMessages.appendChild(messageElement);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    // Open chat with a user
    function openChat(userId, username) {
        activeChat = { id: userId, username: username };
        
        // Update chat header
        document.querySelector('.chat-header h3').textContent = username;
        
        // Clear previous messages
        chatMessages.innerHTML = '';
        
        // Show chat window
        chatWindow.classList.add('active');
        
        // Load chat history
        fetch(`php/get_messages.php?sender=${currentUser.id}&recipient=${userId}`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    data.messages.forEach(message => {
                        appendMessage(message, message.sender === currentUser.id);
                    });
                }
            })
            .catch(error => console.error('Error loading messages:', error));
    }

    // Toggle notifications panel
    function toggleNotifications() {
        notificationPanel.classList.toggle('active');
    }

    // Display notifications
    function displayNotifications() {
        if (!notificationPanel) return;
        
        notificationPanel.innerHTML = '';
        
        if (notifications.length === 0) {
            notificationPanel.innerHTML = '<div class="no-notifications">No notifications</div>';
            return;
        }
        
        notifications.forEach(notification => {
            const notificationElement = document.createElement('div');
            notificationElement.classList.add('notification');
            if (!notification.read) {
                notificationElement.classList.add('unread');
            }
            
            notificationElement.innerHTML = `
                <div class="notification-content">
                    ${notification.content}
                </div>
                <div class="notification-time">${formatTime(notification.timestamp)}</div>
            `;
            
            notificationPanel.appendChild(notificationElement);
        });
        
        // Update notification count
        updateNotificationCount();
    }

    // Update notification count badge
    function updateNotificationCount() {
        const unreadCount = notifications.filter(n => !n.read).length;
        const badge = document.querySelector('.notification-badge');
        
        if (badge) {
            if (unreadCount > 0) {
                badge.textContent = unreadCount;
                badge.style.display = 'flex';
            } else {
                badge.style.display = 'none';
            }
        }
    }

    // Fetch posts from server
    function fetchPosts() {
        fetch('php/get_posts.php')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    posts = data.posts;
                    localStorage.setItem('posts', JSON.stringify(posts));
                    displayPosts();
                }
            })
            .catch(error => {
                console.error('Error fetching posts:', error);
                // Continue with local posts if server is unavailable
                displayPosts();
            });
    }

    // Fetch notifications from server
    function fetchNotifications() {
        if (!currentUser) return;
        
        fetch(`php/get_notifications.php?userId=${currentUser.id}`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    notifications = data.notifications;
                    localStorage.setItem('notifications', JSON.stringify(notifications));
                    displayNotifications();
                }
            })
            .catch(error => {
                console.error('Error fetching notifications:', error);
                // Continue with local notifications if server is unavailable
                displayNotifications();
            });
    }

    // Logout function
    function logout() {
        fetch('php/logout.php')
            .then(response => response.json())
            .then(data => {
                // Clear local data regardless of server response
                localStorage.removeItem('currentUser');
                currentUser = null;
                showAuth();
            })
            .catch(error => {
                console.error('Error logging out:', error);
                // Still log out locally
                localStorage.removeItem('currentUser');
                currentUser = null;
                showAuth();
            });
    }

    // Format timestamp to readable time
    function formatTime(timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const diffMs = now - date;
        const diffSec = Math.floor(diffMs / 1000);
        const diffMin = Math.floor(diffSec / 60);
        const diffHour = Math.floor(diffMin / 60);
        const diffDay = Math.floor(diffHour / 24);
        
        if (diffSec < 60) {
            return 'just now';
        } else if (diffMin < 60) {
            return `${diffMin}m ago`;
        } else if (diffHour < 24) {
            return `${diffHour}h ago`;
        } else if (diffDay < 7) {
            return `${diffDay}d ago`;
        } else {
            return date.toLocaleDateString();
        }
    }
});