#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  const char *name;
  int price;
} MenuItem;

static const MenuItem MENU[6] = {
    {"Overwritten Return Pointer", 1337},         {"Gulasch", 23},
    {"Deep Fried XSS", 13}, {"Pizza Crypto", 11},
    {"Scrambled VM Instruction", 18},      {"Grilled Bits", 6},
};

#define MENU_LENGTH (sizeof(MENU) / sizeof(MENU[0]))

typedef struct {
  char item[32];
  char note[32];
  int price;
} Item;

void print_coupon(void) {
  FILE *f = fopen("/flag", "r");
  if (!f) {
    puts("Could not get valid coupon, sorry");
    return;
  }
  char buf[128];
  if (fgets(buf, sizeof(buf), f)) {
    printf("%s\n", buf);
  }
  fclose(f);
}

void print_menu(void) {
  puts("\n┌────────────────────────────────────────┐");
  puts("│              TODAY'S MENU              │");
  puts("├───┬─────────────────────────────┬──────┤");
  puts("│ # │ Item                        │    $ │");
  puts("├───┼─────────────────────────────┼──────┤");

  for (int i = 0; i < MENU_LENGTH; i++) {
    printf("│ %-1d │ %-27s │ %4d │\n", i + 1, MENU[i].name, MENU[i].price);
  }

  puts("└───┴─────────────────────────────┴──────┘");
}

int calculate_total(Item *order, int n_items) {
  int total = 0;
  puts("\n========== YOUR RECEIPT ==========");
  for (int i = 0; i < n_items; i++) {
    printf("  %-26s $%d\n", order[i].item, order[i].price);
    if (order[i].note[0] != '\0')
      printf("    (note: %.31s)\n", order[i].note);
    total += order[i].price;
  }
  puts("----------------------------------");
  printf("  TOTAL                      $%d\n", total);
  puts("==================================");
  return total;
}

/*
 * Our intern was worried that the sum might overflow.
 * We definitely don't want customers to pay negative prices.
 */
void verify_total(int total) {
  if (total < 0) {
    puts("\n[SYSTEM] Pricing error detected! We sincerely apologise for");
    puts("[SYSTEM] the inconvenience. Please accept this coupon:\n");
    print_coupon();
    exit(0);
  }

  printf("\nPlease proceed to the counter to pay $%d. Enjoy your meal!\n",
         total);
}

void take_order(void) {
  const int order_count = 10;
  Item order[order_count];
  int n_items = 0;
  char input[8];

  puts("\nYou may order up to 10 items. Enter 0 when done.\n");

  while (n_items < order_count) {
    print_menu();
    printf("\nSelect item (1-%d), or 0 to finish: ", (int)MENU_LENGTH);

    if (!fgets(input, sizeof(input), stdin)) {
      break;
    }

    int choice = atoi(input);

    if (choice == 0) {
      break;
    }

    if (choice < 1 || choice > MENU_LENGTH) {
      puts("Invalid choice, please try again.");
      continue;
    }

    Item *cur = &order[n_items];

    strncpy(cur->item, MENU[choice - 1].name, sizeof(cur->item) - 1);
    cur->item[sizeof(cur->item) - 1] = '\0';
    cur->price = MENU[choice - 1].price;

    printf("Any note for the chef? (leave blank for none)\n> ");
    gets(cur->note);

    printf("\nAdded: %s ($%d)\n", cur->item, cur->price);
    n_items++;
  }

  if (n_items == 0) {
    puts("\nNo items ordered. Come back when you're hungry!");
    return;
  }

  int total = calculate_total(order, n_items);
  verify_total(total);
}

int main(void) {
  setbuf(stdout, NULL);
  setbuf(stdin, NULL);

  puts("═══════════════════════════════════════════");
  puts("        GPNCTF Food Ordering System        ");
  puts("     Great Prices. No Vulnerabilities.     ");
  puts("═══════════════════════════════════════════");

  take_order();
  return 0;
}
