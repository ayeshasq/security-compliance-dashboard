import { NextResponse } from 'next/server';
import fs from 'fs';
import path from 'path';

export async function GET() {
  try {
    const dataDir = path.join(process.cwd(), 'public', 'data');
    const scansFile = path.join(dataDir, 'scans.json');
    
    // Check if file exists
    if (!fs.existsSync(scansFile)) {
      return NextResponse.json([]);
    }
    
    // Read and parse the JSON file
    const data = fs.readFileSync(scansFile, 'utf-8');
    const scans = JSON.parse(data);
    
    return NextResponse.json(scans);
  } catch (error) {
    console.error('Error reading scans:', error);
    return NextResponse.json([]);
  }
}

export async function POST(request) {
  try {
    const scanData = await request.json();
    const dataDir = path.join(process.cwd(), 'public', 'data');
    const scansFile = path.join(dataDir, 'scans.json');
    
    // Create directory if it doesn't exist
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    
    // Read existing scans or create empty array
    let scans = [];
    if (fs.existsSync(scansFile)) {
      const data = fs.readFileSync(scansFile, 'utf-8');
      scans = JSON.parse(data);
    }
    
    // Add new scan
    scans.push({
      ...scanData,
      id: Date.now().toString(),
      scanDate: new Date().toISOString()
    });
    
    // Write back to file
    fs.writeFileSync(scansFile, JSON.stringify(scans, null, 2));
    
    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Error saving scan:', error);
    return NextResponse.json({ error: 'Failed to save scan' }, { status: 500 });
  }
}
