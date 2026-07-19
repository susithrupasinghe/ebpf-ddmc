import styles from './Button.module.css';

export function Button({ variant = 'secondary', size = 'md', children, ...props }) {
  return (
    <button
      className={`${styles.btn} ${styles[variant]} ${styles[size]}`}
      {...props}
    >
      {children}
    </button>
  );
}
