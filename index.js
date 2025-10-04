require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const morgan = require('morgan');

const port = process.env.PORT || 9000;
const app = express();
// middleware
const corsOptions = {
   origin: [
      'http://localhost:5173',
      'http://localhost:5174',
      'http://localhost:5173',
   ],
   credentials: true,
   optionSuccessStatus: 200,
};
app.use(cors(corsOptions));

app.use(express.json());
app.use(cookieParser());
app.use(morgan('dev'));

const verifyToken = async (req, res, next) => {
   const token = req.cookies?.token;

   if (!token) {
      return res.status(401).send({ message: 'unauthorized access' });
   }
   jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
      if (err) {
         console.log(err);
         return res.status(401).send({ message: 'unauthorized access' });
      }
      req.user = decoded;
      next();
   });
};

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.wsg3r.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
   serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true,
   },
});
async function run() {
   try {
      const usersCollection = client
         .db('Plant-Net_Collection')
         .collection('users');
      const plantsCollection = client
         .db('Plant-Net_Collection')
         .collection('plants');
      const ordersCollection = client
         .db('Plant-Net_Collection')
         .collection('orders');

      // Verify Admin Middleware
      const verifyAdmin = async (req, res, next) => {
         const { email } = req.user; //This email from JWT email
         const query = { email: email };

         const user = await usersCollection.findOne(query);
         if (!user || user.role !== 'Admin')
            return res
               .status(403)
               .send({ message: 'Forbidden Access! Admin Only Actions!' });

         next();
      };
      // Verify Seller Middleware
      const verifySeller = async (req, res, next) => {
         const { email } = req.user; //This email from JWT email
         const query = { email: email };

         const user = await usersCollection.findOne(query);
         if (!user || user.role !== 'Seller')
            return res
               .status(403)
               .send({ message: 'Forbidden Access! Seller Only Actions!' });

         next();
      };

      // verify email middleware
      const verifyEmail = async (req, res, next) => {
         const jwtEmail = req.user.email;
         const emailParams = req.params.email;
         const emailBody = req.body.email;
         if (jwtEmail !== emailParams || jwtEmail !== emailBody) {
            return res
               .status(401)
               .send({ message: 'Forbidden Access! Email not Match' });
         }
         next();
      };

      // Generate jwt token
      app.post('/jwt', async (req, res) => {
         const email = req.body;
         const token = jwt.sign(email, process.env.ACCESS_TOKEN_SECRET, {
            expiresIn: '365d',
         });
         res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
         }).send({ success: true });
      });
      // Logout
      app.get('/logout', async (req, res) => {
         try {
            res.clearCookie('token', {
               maxAge: 0,
               secure: process.env.NODE_ENV === 'production',
               sameSite:
                  process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            }).send({ success: true });
         } catch (err) {
            res.status(500).send(err);
         }
      });

      // Get user Role
      app.get('/users/role/:email', async (req, res) => {
         const email = req.params.email;
         const result = await usersCollection.findOne({ email });
         // res.send({ role: result?.role });
         res.send({ role: result?.role });
      });

      // Save and Update user when use signUp or googlePopup login
      app.post('/users/:email', async (req, res) => {
         const email = req.params.email;
         const user = req.body;
         const query = { email };

         const isExist = await usersCollection.findOne(query);
         if (isExist) return res.send(isExist);

         const result = await usersCollection.insertOne({
            ...user,
            timestamp: Date.now(),
         });
         res.send(result);
      });

      // Update user Status
      app.patch('/users/:email', async (req, res) => {
         const email = req.params.email;
         const query = { email };

         const user = await usersCollection.findOne(query);
         if (!user || user.status === 'Requested')
            return res
               .status(400)
               .send('You are already requested, wait for some time');
         const updateDoc = {
            $set: {
               status: 'Requested',
            },
         };

         const result = await usersCollection.updateOne(query, updateDoc);
         res.send(result);
      });

      // Get All user Data ::(ONLY ADMIN)
      app.get(
         '/all-users/:email',
         verifyToken,
         verifyAdmin,
         async (req, res) => {
            const email = req.params.email;
            const query = { email: { $ne: email } };
            const result = await usersCollection.find(query).toArray();
            res.send(result);
         }
      );

      // Set user role ans status ::(ONLY ADMIN)
      app.patch(
         '/user/role/:email',
         verifyToken,
         verifyAdmin,
         async (req, res) => {
            const email = req.params.email;
            const { role } = req.body;
            const filter = { email };
            const updateDoc = {
               $set: {
                  role,
                  status: 'Verified',
               },
            };
            const result = await usersCollection.updateOne(filter, updateDoc);
            res.send(result);
         }
      );

      // Save a plant item in DB (::Seller)
      app.post('/plants', verifyToken, verifySeller, async (req, res) => {
         const plantData = req.body;
         const result = await plantsCollection.insertOne(plantData);
         res.send(result);
      });

      // Get inventory data for a specific seller (::Seller) :::::[Here we use jwt user email for query]
      app.get('/plants/seller', verifyToken, verifySeller, async (req, res) => {
         const email = req.user.email;
         console.log(email);
         const query = { 'seller.email': email };
         const result = await plantsCollection.find(query).toArray();
         res.send(result);
      });

      // Delete Plant by Seller (::Seller)
      app.delete('/plants/:id', verifyToken, verifySeller, async (req, res) => {
         const id = req.params.id;
         const query = { _id: new ObjectId(id) };
         const result = await plantsCollection.deleteOne(query);
         res.send(result);
      });

      // Update plant info (::Seller)
      app.put('/plants/:id', verifyToken, verifySeller, async (req, res) => {
         const id = req.params.id;
         const updatePlantData = req.body;
         const filter = { _id: new ObjectId(id) };
         const updateDoc = {
            $set: {
               ...updatePlantData,
            },
         };

         const result = await plantsCollection.updateOne(filter, updateDoc);
         res.send(result);
      });

      // Get all Plants collection data for customer
      app.get('/plants', async (req, res) => {
         const result = await plantsCollection.find().toArray();
         res.send(result);
      });

      // Get a specific plant details by _id
      app.get('/plants/:id', async (req, res) => {
         const id = req.params.id;
         const query = { _id: new ObjectId(id) };
         const result = await plantsCollection.findOne(query);
         res.send(result);
      });

      // Manage Plant quantity
      app.patch('/plants/quantity', verifyToken, async (req, res) => {
         const { quantity, id, status } = req.body;
         const filter = { _id: new ObjectId(id) };
         console.table(typeof quantity);
         let updateDoc = {
            $inc: {
               quantity: -quantity,
            },
         };
         if (status === 'increase') {
            updateDoc = {
               $inc: {
                  quantity: quantity,
               },
            };
         }
         const result = await plantsCollection.updateOne(filter, updateDoc);
         res.send(result);
      });

      // Save Order dta in DB
      app.post('/orders', verifyToken, async (req, res) => {
         const orderInfo = req.body;
         const result = await ordersCollection.insertOne(orderInfo);
         res.send(result);
      });

      //Get user order data by user email (AGGREGATE)
      app.get('/orders/:email', verifyToken, async (req, res) => {
         const email = req.params.email;
         const query = { 'customer.email': email };
         const orderData = await ordersCollection
            .aggregate([
               {
                  $match: query, //Match specific customer orderData
               },
               {
                  $addFields: { plantId: { $toObjectId: '$plantId' } }, //NMake a plantId string to ObjectId
               },
               {
                  $lookup: {
                     from: 'plants',
                     localField: 'plantId', //Join daata to plant data
                     foreignField: '_id',
                     as: 'plantData',
                  },
               },
               {
                  $unwind: '$plantData', //Leave plantData from Array[]
               },
               {
                  $addFields: {
                     plantName: '$plantData.plantName',
                     plantImage: '$plantData.image',
                     plantCategory: '$plantData.category', //Add specific data from plantDta
                     // plantPrice: '$plantData.price',
                  },
               },
               {
                  $project: {
                     plantData: 0, //Remove plantData
                  },
               },
            ])
            .toArray();

         res.send(orderData);
      });

      // Get order data for specific  seller  (::SELLER)
      app.get(
         '/orders/seller/:email',

         verifyToken,
         verifySeller,
         async (req, res) => {
            const sellerEmail = req.params.email;
            const query = { seller: sellerEmail };

            const sellerOrders = await ordersCollection
               .aggregate([
                  {
                     $match: query,
                  },
                  {
                     $addFields: { plantId: { $toObjectId: '$plantId' } },
                  },
                  {
                     $lookup: {
                        from: 'plants',
                        localField: 'plantId',
                        foreignField: '_id',
                        as: 'plant',
                     },
                  },
                  {
                     $unwind: '$plant',
                  },
                  {
                     $addFields: {
                        plantName: '$plant.plantName',
                     },
                  },
                  {
                     $project: {
                        plant: 0,
                     },
                  },
               ])
               .toArray();

            res.send(sellerOrders);
         }
      );

      // Cancel Order By Seller (::SELLER)
      app.delete(
         '/orders/seller/:id',
         verifyToken,
         verifySeller,
         async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await ordersCollection.deleteOne(query);
            res.send(result);
         }
      );

      // Update order Status by Seller (::SELLER)
      app.patch(
         '/orders/seller/:id',
         verifyToken,
         verifySeller,
         async (req, res) => {
            const id = req.params.id;
            const { status } = req.body;
            const query = { _id: new ObjectId(id) };
            const updateDoc = {
               $set: {
                  status,
               },
            };

            const result = await ordersCollection.updateOne(query, updateDoc);
            res.send(result);
         }
      );

      // Delete order Data by Customer
      app.delete('/orders/:id', verifyToken, async (req, res) => {
         const id = req.params.id;
         const query = { _id: new ObjectId(id) };
         const order = await ordersCollection.findOne(query);
         if (order.status === 'Delivered')
            return res
               .status(409)
               .send('Cannot Cancel Once The Product is Delivered');

         const result = await ordersCollection.deleteOne(query);
         res.send(result);
      });

      // Send a ping to confirm a successful connection
      // await client.db('admin').command({ ping: 1 });
      console.log(
         'Pinged your deployment. You successfully connected to MongoDB!'
      );
   } finally {
      // Ensures that the client will close when you finish/error
   }
}
run().catch(console.dir);

app.get('/', (req, res) => {
   res.send('Hello from plantNet Server..');
});

app.listen(port, () => {
   console.log(`plantNet is running on port ${port}`);
});
