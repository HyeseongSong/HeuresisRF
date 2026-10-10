import { NextResponse } from 'next/server';

export async function GET() {
  return NextResponse.json({ message: 'This endpoint is meant to ingest data! It is not accessible via GET.' });
}

export async function POST(request: Request) {
  const body = await request.json();
  return NextResponse.json({ received: body }, { status: 200 });
}