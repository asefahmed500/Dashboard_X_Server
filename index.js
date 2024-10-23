require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const webpush = require('web-push');

const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const { count } = require('console');


const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());




const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.8vksczm.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server (optional starting in v4.7)
    await client.connect();

    const UserCollection = client.db("Dashboard").collection("users");
    const TaskCollection = client.db("Dashboard").collection("task");
    const SentTasksCollection = client.db("Dashboard").collection("sent_tasks");
    const PaymnetCollection = client.db("Dashboard").collection("payments");
    const TaskStatusColletion = client.db("Dashboard").collection("taskstatus")
    const PaymentAcceptanceCollection = client.db('Dashboard').collection('paymentacceptances');
    const MessageCollection = client.db('Dashboard').collection('message');
    const ContactMessageCollection = client.db('Dashboard').collection('Contactmessage');





    // JWT token generation API
    app.post('/jwt', async (req, res) => {
      const { email } = req.body;
      const user = await UserCollection.findOne({ email });

      if (!user) {
        return res.status(404).send({ message: 'User not found' });
      }

      const tokenPayload = { email: user.email, role: user.role };  // Include role in the payload
      const token = jwt.sign(tokenPayload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
      res.send({ token });
    });

    // Middleware for verifying tokens
    const verifyToken = (req, res, next) => {
      if (!req.headers.authorization) {
        console.log('Authorization header missing.'); // Log if no auth header
        return res.status(401).send({ message: 'Forbidden Access' });
      }
      const token = req.headers.authorization.split(' ')[1];
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
          console.log('Token verification failed:', err); // Log verification failure
          return res.status(401).send({ message: 'Unauthorized access' });
        }
        console.log('Decoded token:', decoded); // Log the decoded token
        req.decoded = decoded;
        next();
      });
    };


    // Middleware to verify admin role
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const user = await UserCollection.findOne({ email });
      if (user?.role !== 'admin') {
        return res.status(403).send({ message: 'Unauthorized access' });
      }
      next();
    };

    // Middleware to verify staff role
    const verifyStaff = async (req, res, next) => {
      const email = req.decoded.email;
      const user = await UserCollection.findOne({ email });
      if (user?.role !== 'staff') {
        return res.status(403).send({ message: 'Unauthorized access' });
      }
      next();
    };

    // Middleware to verify guard role
    const verifyGuard = async (req, res, next) => {
      const email = req.decoded.email;
      const user = await UserCollection.findOne({ email });
      if (user?.role !== 'guard') {
        return res.status(403).send({ message: 'Unauthorized access' });
      }
      next();
    };

    // user Role 

    // API to get the user's role
    app.get('/users/role/:email', verifyToken, async (req, res) => {
      const email = req.params.email;

      // Check if the email in the token matches the email in the request
      if (email !== req.decoded.email) {
        return res.status(403).send({ message: 'Forbidden access' });
      }

      try {
        // Find the user by email
        const user = await UserCollection.findOne({ email });

        // If user is not found, return an error
        if (!user) {
          return res.status(404).send({ message: 'User not found' });
        }

        // Return the user's role
        res.send({ role: user.role });
      } catch (error) {
        console.error('Error fetching user role:', error);
        res.status(500).send({ message: 'Internal server error' });
      }
    });


    // Admin APIs
    app.get('/users/admin/:email', verifyToken, async (req, res) => {
      const email = req.params.email;
      if (email !== req.decoded.email) {
        return res.status(403).send({ message: 'Forbidden access' });
      }
      const user = await UserCollection.findOne({ email });
      res.send({ admin: user?.role === 'admin' });
    });

    app.patch('/users/admin/:id', verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = { $set: { role: 'admin' } };
      const result = await UserCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    // Staff APIs
    app.get('/users/staff/:email', verifyToken, async (req, res) => {
      const email = req.params.email;
      if (email !== req.decoded.email) {
        return res.status(403).send({ message: 'Forbidden access' });
      }
      const user = await UserCollection.findOne({ email });
      res.send({ staff: user?.role === 'staff' });
    });

    app.patch('/users/staff/:id', verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = { $set: { role: 'staff' } };
      const result = await UserCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    // Guard APIs

    app.get('/users/guard/:email', verifyToken, async (req, res) => {
      const email = req.params.email;
      if (email !== req.decoded.email) {
        return res.status(403).send({ message: 'Forbidden access' });
      }

      try {
        const user = await UserCollection.findOne({ email });
        if (!user) {
          return res.status(404).send({ message: 'User not found' });
        }
        res.send({ guard: user?.role === 'guard' });
      } catch (error) {
        res.status(500).send({ message: 'Error fetching user data' });
      }
    });




    app.patch('/users/guard/:id', verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      console.log('Patch request for id:', id);

      try {
        const filter = { _id: new ObjectId(id) };
        const updateDoc = { $set: { role: 'guard' } };
        const result = await UserCollection.updateOne(filter, updateDoc);

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: 'User not found' });
        }

        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Error updating user role' });
      }
    });

    // Get all users
    app.get('/users', verifyToken, async (req, res) => {
      try {
        const result = await UserCollection.find().toArray();
        res.send(result);
      } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send({ message: 'Internal server error' });
      }
    });

    // Add a new user
    app.post('/users', async (req, res) => {
      try {
        const { email, name } = req.body;

        // Basic validation
        if (!email || !name) {
          return res.status(400).json({ message: 'Email and name are required', insertedId: null });
        }

        // Check if user already exists
        const existingUser = await UserCollection.findOne({ email });
        if (existingUser) {
          return res.status(409).json({ message: 'User already exists', insertedId: null });
        }

        // Insert new user
        const result = await UserCollection.insertOne({ email, name });
        res.status(201).json({ message: 'User created successfully', insertedId: result.insertedId });

      } catch (error) {
        console.error('Error inserting user:', error);
        res.status(500).json({ message: 'Internal server error', error: error.message });
      }
    });


    app.delete('/users/:id', verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await UserCollection.deleteOne(query);
      res.send(result);
    })

    // task Apis


    // GET API to retrieve all tasks
    app.get('/tasks', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const tasks = await TaskCollection.find().toArray(); // Retrieve all tasks
        return res.status(200).json(tasks); // Send the tasks data
      } catch (error) {
        console.error('Error retrieving tasks:', error);
        return res.status(500).send('Error retrieving tasks');
      }
    });



    // GET API to retrieve a task by ID
    app.get('/tasks/:id', verifyToken, async (req, res) => {
      const { id } = req.params;

      // Validate the ObjectId format
      if (!ObjectId.isValid(id)) {
        console.error('Invalid ID format:', id);
        return res.status(400).send('Invalid ID format');
      }

      try {
        const task = await TaskCollection.findOne({ _id: new ObjectId(id) });
        if (!task) {
          return res.status(404).send('Task not found.');
        }
        return res.status(200).json(task);
      } catch (error) {
        console.error('Error fetching task:', error);
        return res.status(500).send('Error fetching task');
      }
    });



    // DELETE API to remove a task by ID
    app.delete('/tasks/:id', verifyToken, verifyAdmin, async (req, res) => {
      const { id } = req.params;
      try {
        const result = await TaskCollection.deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) {
          return res.status(404).json({ message: 'Task not found', deletedCount: 0 });
        }
        return res.status(200).json({ message: 'Task deleted successfully', deletedCount: result.deletedCount });
      } catch (error) {
        console.error('Error deleting task:', error);
        return res.status(500).json({ message: 'Error deleting task' });
      }
    });


    app.patch('/tasks/:id', verifyToken, verifyAdmin, async (req, res) => {
      const { id } = req.params;
      const updatedData = req.body; // Incoming updated task data

      // Validate the ObjectId format
      if (!/^[0-9a-f]{24}$/.test(id)) {
        console.error('Invalid ID format:', id);
        return res.status(400).send('Invalid ID format');
      }

      try {
        // Retrieve the existing task data
        const existingTask = await TaskCollection.findOne({ _id: new ObjectId(id) });

        // Check if task exists
        if (!existingTask) {
          return res.status(404).send('Task not found.');
        }

        // Compare existing data with updated data
        const hasChanges = Object.keys(updatedData).some(key => existingTask[key] !== updatedData[key]);

        if (!hasChanges) {
          return res.status(200).send('No changes detected. Your task is already up to date.');
        }

        // Proceed with the update if there are changes
        const result = await TaskCollection.updateOne(
          { _id: new ObjectId(id) }, // Use ObjectId constructor
          { $set: updatedData } // Use $set to update specific fields
        );

        if (result.modifiedCount === 0) {
          return res.status(404).send('No changes made or task not found.');
        }

        return res.status(200).json({
          message: 'Task updated successfully.',
          modifiedCount: result.modifiedCount
        });
      } catch (error) {
        console.error('Error updating task:', error);
        return res.status(500).send('Error updating task');
      }
    });



    app.post('/tasks', verifyToken, verifyAdmin, async (req, res) => {
      const { title, description, fileUrl } = req.body;

      console.log('Received Task Data:', { title, description, fileUrl }); // Log received task data

      if (!title || !description || !fileUrl) {
        console.log('Validation Error: All fields are required.'); // Log validation error
        return res.status(400).send('All fields are required.');
      }

      try {
        const newTask = {
          title,
          description,
          fileUrl,
        };

        const result = await TaskCollection.insertOne(newTask);
        if (result.insertedId) {
          return res.status(201).json({ insertedId: result.insertedId });
        }
      } catch (error) {
        console.error('Error adding task:', error); // Log any errors
        res.status(500).send('Error adding task');
      }
    });

    // API to send task data to another user
    app.post('/send-task', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const { recipientEmail, taskId } = req.body;

        // Validate email format
        const isValidEmail = (email) => {
          const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
          return re.test(String(email).toLowerCase());
        };

        if (!isValidEmail(recipientEmail)) {
          return res.status(400).send({ message: 'Invalid email format' });
        }

        // Fetch the task by taskId
        const task = await TaskCollection.findOne({ _id: new ObjectId(taskId) });
        if (!task) return res.status(404).send({ message: 'Task not found.' });

        // Get the sender's email dynamically (based on the logged-in admin user)
        const senderEmail = req.decoded.email;

        const msg = {
          to: recipientEmail,
          from: senderEmail, // Use the logged-in admin's email as the sender
          subject: `Task: ${task.title}`,
          text: `Here are the task details: \nTitle: ${task.title}\nDescription: ${task.description}\nFile: ${task.fileUrl}`,
        };

        // Send the email
        await sgMail.send(msg);

        // Log the sent task in the database with more details
        const logEntry = {
          taskId: taskId,
          recipientEmail: recipientEmail,
          senderEmail: senderEmail, // Log the sender's email
          title: task.title,         // Include task title
          description: task.description, // Include task description
          sentAt: new Date(),        // Record the timestamp
        };

        await SentTasksCollection.insertOne(logEntry); // Insert log entry into the sent_tasks collection

        res.status(200).send({ message: 'Task sent successfully' });
      } catch (error) {
        console.error('Error sending email:', error.response?.body?.errors || error);
        res.status(500).send({ message: 'Failed to send email', errors: error.response?.body?.errors || [] });
      }
    });


    app.get('/sent-tasks', verifyToken, async (req, res) => {
      const email = req.decoded.email;

      const sentTasks = await SentTasksCollection.find({ recipientEmail: email }).toArray();

      const tasksWithDetails = await Promise.all(sentTasks.map(async (sentTask) => {
        const task = await TaskCollection.findOne({ _id: new ObjectId(sentTask.taskId) });
        return { ...sentTask, task }; // Combine sent task data with the corresponding task details
      }));

      res.send(tasksWithDetails);
    });

    // admin view task new

    // Task Status 



    app.get('/taskshistory', async (req, res) => {
      try {
        const taskStatuses = await TaskStatusColletion.find().toArray(); // Corrected collection name
        res.status(200).send(taskStatuses); // Send all task statuses
      } catch (error) {
        console.error('Error fetching task status history:', error);
        res.status(500).send({ message: error.message });
      }
    });



    app.post('/tasks/status', async (req, res) => {
      const { taskId, status, email } = req.body;

      // Validate the input
      if (!taskId || !status || !email) {
        return res.status(400).json({ message: 'Missing required fields.' });
      }

      try {
        // Insert or replace the task status in taskStatus collection
        const result = await TaskStatusColletion.insertOne({
          email: email,
          taskId: new ObjectId(taskId),  // Ensure taskId is an ObjectId
          status: status,
        });

        // Check if the insertion was successful
        if (!result.acknowledged) {
          return res.status(500).json({ message: 'Failed to insert task status.' });
        }

        // Remove the task from the sent_tasks collection
        const deleteResult = await SentTasksCollection.deleteOne({ _id: new ObjectId(taskId) });

        // Check if the deletion was successful
        if (deleteResult.deletedCount === 0) {
          return res.status(404).json({ message: 'Task not found or already deleted.' });
        }

        res.status(201).json({ message: 'Task status updated and task removed successfully.' });
      } catch (error) {
        console.error('Error processing task status:', error);
        res.status(500).json({ message: 'Error processing task status.' });
      }
    });






    // payemnt staus 

    app.post('/payments/accept', async (req, res) => {
      const { paymentId, email } = req.body; // Get payment ID and user email from request body

      try {
        // Store the payment acceptance in the database
        const result = await PaymentAcceptanceCollection.updateOne(
          { _id: new ObjectId(paymentId) },  // Match by payment ID
          { $set: { accepted: true, acceptedBy: email, acceptedAt: new Date() } },  // Store acceptance info
          { upsert: true }  // Insert if it doesn't exist
        );

        res.status(200).send({ message: 'Payment accepted successfully' });
      } catch (error) {
        console.error('Error accepting payment:', error);
        res.status(500).send({ message: 'Failed to accept payment' });
      }
      // DO NOT close the client here
    });

    app.get('/payment-info/:email', async (req, res) => {
      const { email } = req.params;

      try {
        // Fetch all payment info for the user by email
        const paymentInfo = await PaymnetCollection.find({ email }).toArray();

        if (paymentInfo.length === 0) {
          return res.status(404).send({ message: 'No payment information found for this email.' });
        }

        // Fetch accepted payments for this user from the acceptance collection
        const acceptedPayments = await PaymentAcceptanceCollection.find({ acceptedBy: email }).toArray();
        const acceptedPaymentIds = acceptedPayments.map(payment => payment._id.toString());

        // Filter out accepted payments
        const unacceptedPayments = paymentInfo.filter(payment => !acceptedPaymentIds.includes(payment._id.toString()));

        res.send(unacceptedPayments);
      } catch (error) {
        console.error('Error fetching payment information:', error);
        res.status(500).send({ message: 'Failed to fetch payment information' });
      }
      // DO NOT close the client here
    });


    app.get('/payment-history', async (req, res) => {
      try {
        const paymentHistory = await PaymnetCollection.find().toArray(); // Fetch all payment records
        res.send(paymentHistory);
      } catch (error) {
        console.error('Error fetching payment history:', error);
        res.status(500).send({ message: error.message });
      }
    });




    app.post('/create-payment-intent', async (req, res) => {
      const { amount, name, role, email } = req.body; // Destructure email from the request body

      try {
        const paymentIntent = await stripe.paymentIntents.create({
          amount,
          currency: 'usd',
          automatic_payment_methods: {
            enabled: true,
          },
        });

        // Store payment information in MongoDB
        const paymentInfo = {
          amount: amount / 100, // Store amount in dollars
          currency: 'usd',
          status: paymentIntent.status,
          client_secret: paymentIntent.client_secret,
          name,
          role,
          email, // Store the email
          created_at: new Date(),
        };

        // Use the already defined PaymnetCollection
        await PaymnetCollection.insertOne(paymentInfo); // Save payment info to MongoDB

        res.send({ clientSecret: paymentIntent.client_secret });
      } catch (error) {
        console.error('Error creating payment intent:', error);
        res.status(500).send({ message: error.message });
      }
    });

    // message 

    app.post('/messages', async (req, res) => {
      const { sender, recipient, content, timestamp } = req.body; // Include recipient

      // Validate required fields
      if (!sender || !recipient || !content) {
        return res.status(400).send({ message: 'Sender, recipient, and content are required.' });
      }

      const message = { sender, recipient, content, timestamp };

      try {
        await MessageCollection.insertOne(message);
        res.status(201).json(message);
      } catch (error) {
        console.error('Error saving message:', error);
        res.status(500).send('Internal Server Error');
      }
    });

    // GET route to fetch messages for a specific user
    app.get('/messages', async (req, res) => {
      const { user1, user2 } = req.query; // Expect two users to be passed as query parameters

      try {
        const messages = await MessageCollection.find({
          $or: [
            // Fetch messages where user1 is the sender and user2 is the recipient, or vice versa
            { sender: user1, recipient: user2 },
            { sender: user2, recipient: user1 }
          ]
        })
          .sort({ timestamp: 1 }) // Sort by timestamp in ascending order
          .toArray();

        res.status(200).json(messages);
      } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).send('Internal Server Error');
      }
    });

    // contact 


    app.post('/contact', async (req, res) => {
      const { name, email, message } = req.body;
      const result = await ContactMessageCollection.insertOne({
        name,
        email,
        message,
        date: new Date()
      })
      res.status(200).json({ message: 'Message sent successfully!', result });
    })

    // stats 

    app.get('/admin/stats', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const userStats = await UserCollection.aggregate([
          {
            $group: {
              _id: "$role",
              count: {
                $sum: 1
              }
            }
          }
        ]).toArray();

        const paymentStats = await PaymnetCollection.aggregate([
          {
            $group: {
              _id: "$status", count: {
                $sum: 1
              }
            }
          }
        ]).toArray();
        const taskStats = await TaskStatusColletion.aggregate([
          { $group: { _id: "$status", count: { $sum: 1 } } }
        ]).toArray();

        // Get all salary acceptance stats
        const salaryAcceptance = await PaymentAcceptanceCollection.aggregate([
          { $group: { _id: "$accepted", count: { $sum: 1 } } }
        ]).toArray();

        // Get all messages sent to the admin
        const adminMessages = await MessageCollection.find({ recipient: "admin" }).toArray();

        res.send({
          userStats,
          paymentStats,
          taskStats,
          salaryAcceptance,
          adminMessages
        });


      }
      catch (error) {
        //
        console.error('Error fetching admin stats:', error);
        res.status(500).send({ message: 'Error fetching stats' });
      }
    })

    // // Guard Stats API
    app.get('/guard/stats', verifyToken, verifyGuard, async (req, res) => {
      try {
        const email = req.decoded.email;

        // Fetch assigned tasks
        const tasks = await TaskCollection.find({ assignedTo: email }).toArray();

        // Fetch task completion status
        const taskStats = await TaskStatusColletion.find({ email }).toArray();

        // Fetch salary acceptance status
        const payment = await PaymentAcceptanceCollection.findOne({ acceptedBy: email });

        // Fetch messages
        const messages = await MessageCollection.find({ recipient: email }).toArray();

        res.send({
          tasks,
          taskStats,
          paymentStatus: payment?.accepted ? 'Accepted' : 'Not Accepted',
          messages
        });
      } catch (error) {
        console.error('Error fetching guard stats:', error);
        res.status(500).send({ message: 'Error fetching stats' });
      }
    });

    // Staff Stats API
    app.get('/staff/stats', verifyToken, verifyStaff, async (req, res) => {
      try {
        const email = req.decoded.email;

        // Fetch assigned tasks
        const tasks = await TaskCollection.find({ assignedTo: email }).toArray();

        // Fetch task completion status
        const taskStats = await TaskStatusColletion.find({ email }).toArray();

        // Fetch salary acceptance status
        const payment = await PaymentAcceptanceCollection.findOne({ acceptedBy: email });

        // Fetch messages
        const messages = await MessageCollection.find({ recipient: email }).toArray();

        res.send({
          tasks,
          taskStats,
          paymentStatus: payment?.accepted ? 'Accepted' : 'Not Accepted',
          messages
        });
      } catch (error) {
        console.error('Error fetching staff stats:', error);
        res.status(500).send({ message: 'Error fetching stats' });
      }
    });

    // User Stats API
    app.get('/user/stats', verifyToken, async (req, res) => {
      try {
        const email = req.decoded.email;

        // Fetch assigned tasks
        const tasks = await TaskCollection.find({ assignedTo: email }).toArray();

        // Fetch task completion status
        const taskStats = await TaskStatusColletion.find({ email }).toArray();

        // Fetch salary acceptance status (if applicable)
        const payment = await PaymentAcceptanceCollection.findOne({ acceptedBy: email });

        // Fetch messages
        const messages = await MessageCollection.find({ recipient: email }).toArray();

        res.send({
          tasks,
          taskStats,
          paymentStatus: payment?.accepted ? 'Accepted' : 'Not Accepted',
          messages
        });
      } catch (error) {
        console.error('Error fetching user stats:', error);
        res.status(500).send({ message: 'Error fetching stats' });
      }
    });













    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Keep the MongoDB connection alive
    // await client.close(); // Optional, remove in production
  }
}
run().catch(console.dir);

// Root route
app.get('/', (req, res) => {
  res.send('Dashboard X server is Running!');
});

app.listen(port, () => {
  console.log(`Dashboard X app listening on port ${port}`);
});
