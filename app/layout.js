import './globals.css'

export const metadata = {
  title: 'Security Compliance Dashboard',
  description: 'Monitor your security compliance in real-time',
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
