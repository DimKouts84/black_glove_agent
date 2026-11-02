import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { MarkdownBody } from './MarkdownBody';

describe('MarkdownBody', () => {
  it('renders a pipe table as a table with header cells', () => {
    render(
      <MarkdownBody>
        {'| Severity | Finding |\n| --- | --- |\n| HIGH | Missing CSP |'}
      </MarkdownBody>,
    );
    const table = screen.getByRole('table');
    expect(table).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Severity' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Finding' })).toBeTruthy();
    expect(screen.getByRole('cell', { name: 'Missing CSP' })).toBeTruthy();
  });
});
