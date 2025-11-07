// Quick test to check database directly
// Run: node check-database.js

require('dotenv').config();
const mongoose = require('mongoose');

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/campaignwala';

async function checkDatabase() {
  try {
    console.log('🔌 Connecting to MongoDB...');
    console.log('   URI:', MONGODB_URI.replace(/:[^:]*@/, ':****@')); // Hide password
    
    await mongoose.connect(MONGODB_URI);
    console.log('✅ Connected to MongoDB\n');

    // Check Leads collection
    const Lead = mongoose.model('Lead', new mongoose.Schema({}, { strict: false }), 'leads');
    
    console.log('📊 LEADS COLLECTION CHECK:');
    console.log('=' .repeat(60));
    
    const totalLeads = await Lead.countDocuments();
    console.log(`Total leads in database: ${totalLeads}`);
    
    if (totalLeads === 0) {
      console.log('❌ NO LEADS FOUND! Database is empty.');
      console.log('\n💡 Solution: Add some leads to the database first.');
      process.exit(0);
    }
    
    console.log('\n📋 Status breakdown:');
    const pending = await Lead.countDocuments({ status: 'pending' });
    const approved = await Lead.countDocuments({ status: 'approved' });
    const completed = await Lead.countDocuments({ status: 'completed' });
    const rejected = await Lead.countDocuments({ status: 'rejected' });
    
    console.log(`   Pending: ${pending}`);
    console.log(`   Approved: ${approved}`);
    console.log(`   Completed: ${completed}`);
    console.log(`   Rejected: ${rejected}`);
    
    console.log('\n📅 Date information:');
    const oldestLead = await Lead.findOne().sort({ createdAt: 1 });
    const newestLead = await Lead.findOne().sort({ createdAt: -1 });
    
    if (oldestLead && newestLead) {
      console.log(`   Oldest lead: ${oldestLead.createdAt}`);
      console.log(`   Newest lead: ${newestLead.createdAt}`);
      
      const oldestDate = new Date(oldestLead.createdAt);
      const newestDate = new Date(newestLead.createdAt);
      const daysDiff = Math.ceil((newestDate - oldestDate) / (1000 * 60 * 60 * 24));
      console.log(`   Date range: ${daysDiff} days`);
    }
    
    console.log('\n🏷️ Categories found:');
    const categories = await Lead.distinct('category');
    categories.forEach(cat => {
      console.log(`   - ${cat}`);
    });
    
    console.log('\n👥 Sample leads (latest 3):');
    const sampleLeads = await Lead.find().sort({ createdAt: -1 }).limit(3);
    sampleLeads.forEach((lead, idx) => {
      console.log(`   ${idx + 1}. ${lead._id}`);
      console.log(`      Category: ${lead.category || 'N/A'}`);
      console.log(`      Status: ${lead.status || 'N/A'}`);
      console.log(`      Created: ${lead.createdAt}`);
    });
    
    console.log('\n' + '='.repeat(60));
    console.log('✅ Database check completed!');
    console.log('\n📌 Suggested date range for analytics:');
    if (oldestLead && newestLead) {
      const start = new Date(oldestLead.createdAt);
      const end = new Date(newestLead.createdAt);
      console.log(`   Start: ${start.toISOString().split('T')[0]}`);
      console.log(`   End: ${end.toISOString().split('T')[0]}`);
    }
    
    mongoose.connection.close();
  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

checkDatabase();
