import { render, screen } from '@testing-library/react';
import { vi } from 'vitest';
import App from '../App';

describe('App', () => {
  it('renders login form initially', () => {
    render(<App />);
    expect(screen.getByLabelText('Username input')).toBeInTheDocument();
    expect(screen.getByLabelText('Password input')).toBeInTheDocument();
    expect(screen.getByLabelText('Login button')).toBeInTheDocument();
  });

  it('matches snapshot with dark mode', () => {
    const { container } = render(<App />);
    expect(container).toMatchSnapshot();
  });

  it('matches snapshot with light mode', () => {
    const { container } = render(<App />);
    // Simulate light mode toggle
    container.querySelector('input[type="checkbox"]')?.click();
    expect(container).toMatchSnapshot();
  });
});