// Simple script to test Analytics API endpoints
// Run: node test-analytics-api.js

const API_BASE = 'http://localhost:3000/api';

// Simple fetch wrapper
async function testEndpoint(name, url) {
  console.log(`\n🧪 Testing ${name}...`);
  console.log(`   URL: ${url}`);
  
  try {
    const response = await fetch(url);
    const data = await response.json();
    
    if (response.ok) {
      console.log(`   ✅ Status: ${response.status} OK`);
      console.log(`   📦 Data:`, JSON.stringify(data, null, 2));
      return data;
    } else {
      console.log(`   ❌ Status: ${response.status}`);
      console.log(`   📦 Error:`, data);
      return null;
    }
  } catch (error) {
    console.log(`   ❌ Error: ${error.message}`);
    return null;
  }
}

async function runTests() {
  console.log('🚀 Starting API Tests...');
  console.log('📍 Base URL:', API_BASE);
  console.log('=' .repeat(60));

  // Test 1: Health Check
  await testEndpoint('Health Check', `${API_BASE}/health`);

  // Test 2: Get Users
  const usersData = await testEndpoint('Get Users', `${API_BASE}/leads/users`);
  if (usersData && usersData.data) {
    console.log(`   📊 Users found: ${usersData.data.length}`);
  }

  // Test 3: Get Analytics
  const today = new Date();
  const thirtyDaysAgo = new Date(today);
  thirtyDaysAgo.setDate(today.getDate() - 30);
  
  const startDate = thirtyDaysAgo.toISOString().split('T')[0];
  const endDate = today.toISOString().split('T')[0];
  
  const analyticsUrl = `${API_BASE}/leads/analytics?startDate=${startDate}&endDate=${endDate}`;
  const analyticsData = await testEndpoint('Get Analytics', analyticsUrl);
  
  if (analyticsData && analyticsData.data) {
    console.log(`   📊 Metrics:`, analyticsData.data.metrics);
    console.log(`   📊 Date-wise data points: ${analyticsData.data.dateWiseData.length}`);
    console.log(`   📊 Categories: ${analyticsData.data.categoryDistribution.length}`);
  }

  console.log('\n' + '='.repeat(60));
  console.log('✅ Tests completed!');
  console.log('\nIf all tests passed, your backend is working correctly.');
  console.log('If tests failed, check:');
  console.log('  1. Backend server is running');
  console.log('  2. Port number is correct (default: 3000)');
  console.log('  3. MongoDB is connected');
  console.log('  4. Database has some lead data');
}

runTests().catch(console.error);
